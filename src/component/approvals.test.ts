import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import type {Id} from './_generated/dataModel.js';
import {expectFail, initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const SUBJECT = 'user_alice';
const APPROVER = 'admin_bob';

async function auditRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('audit').collect());
}
async function toolCallRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('toolCalls').collect());
}
async function approvalRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('approvals').collect());
}
async function auditByCorrelation(t: ConvexTest, correlationId: string) {
  return await t.run(async (ctx) =>
    ctx.db
      .query('audit')
      .withIndex('by_correlation', (q) => q.eq('correlationId', correlationId))
      .collect()
  );
}

/** Recover the approvalId from an approve decision (typed, no non-null assertion). */
function approvalIdOf(res: {
  decision: string;
  approvalId?: Id<'approvals'>;
}): Id<'approvals'> {
  if (res.decision !== 'approve' || res.approvalId === undefined) {
    throw new Error(`expected an approve decision, got ${res.decision}`);
  }
  return res.approvalId;
}

/** Grant a tool at a given risk level and return the checkTool result. */
async function checkHighRiskGrant(t: ConvexTest, tool = 'wire_transfer') {
  await t.mutation(api.policy.grant, {subject: SUBJECT, tool, risk: 'high'});
  return await t.mutation(api.enforce.checkTool, {subject: SUBJECT, tool});
}

describe('risk gate → approve (public component API)', () => {
  test('high-risk grant that passes allowlist+args → approve, with exact 1/1/1 counts', async () => {
    const t = initConvexTest();
    const res = await checkHighRiskGrant(t);

    expect(res.decision).toBe('approve');
    const approvalId = approvalIdOf(res);

    // Exactly ONE audit row: decision 'approve', reason 'approval_required'.
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('approve');
    expect(audits[0].reason).toBe('approval_required');

    // Exactly ONE toolCalls row with approvalId set (back-reference).
    const calls = await toolCallRows(t);
    expect(calls).toHaveLength(1);
    expect(calls[0].decision).toBe('approve');
    expect(calls[0].approvalId).toBe(approvalId);

    // Exactly ONE approvals row, pending, linked to the call, carrying risk.
    const approvals = await approvalRows(t);
    expect(approvals).toHaveLength(1);
    expect(approvals[0]._id).toBe(approvalId);
    expect(approvals[0].status).toBe('pending');
    expect(approvals[0].toolCallRef).toBe(calls[0]._id);
    expect(approvals[0].policy).toBe('high');
    expect(approvals[0].correlationId).toBe(res.correlationId);
  });

  test('policy-set high risk (no grant risk) also routes to approve', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'deploy'});
    await t.mutation(api.policy.setToolRisk, {tool: 'deploy', level: 'high'});
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'deploy'
    });
    expect(res.decision).toBe('approve');
  });

  test('regression: a non-high-risk tool still returns allow (P1/P2 path)', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'search',
      risk: 'medium'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(res.decision).toBe('allow');
    expect(res.approvalId).toBeUndefined();
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('allow');
  });

  test('deny-by-default WINS over risk: out-of-allowlist high-risk tool → deny no_grant', async () => {
    const t = initConvexTest();
    // Tool is marked high-risk at the policy level, but the subject has NO grant.
    await t.mutation(api.policy.setToolRisk, {
      tool: 'wire_transfer',
      level: 'high'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire_transfer'
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('no_grant');
    // No approval was created — risk is evaluated AFTER allowlist.
    expect(await approvalRows(t)).toHaveLength(0);
  });

  test('argument policy still denies before risk: over-cap high-risk → argument_denied', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire_transfer',
      risk: 'high',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire_transfer',
      args: {amount: 500}
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('argument_denied');
    expect(await approvalRows(t)).toHaveLength(0);
  });
});

describe('approval resolution', () => {
  test('approve → status approved, resolver recorded, audit trail approve→approval_approved', async () => {
    const t = initConvexTest();
    const res = await checkHighRiskGrant(t);
    const approvalId = approvalIdOf(res);

    await t.mutation(api.approvals.approve, {approvalId, approver: APPROVER});

    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.status).toBe('approved');
    expect(status?.resolvedBy).toBe(APPROVER);
    expect(status?.resolvedAt).not.toBeNull();

    const trail = await auditByCorrelation(t, res.correlationId);
    expect(trail.map((r) => r.reason)).toEqual([
      'approval_required',
      'approval_approved'
    ]);
    // Both rows keep decision 'approve' — the resolution never writes allow/deny.
    expect(trail.every((r) => r.decision === 'approve')).toBe(true);
  });

  test('deny → status denied, reason + resolver recorded, audit approval_denied', async () => {
    const t = initConvexTest();
    const res = await checkHighRiskGrant(t);
    const approvalId = approvalIdOf(res);

    await t.mutation(api.approvals.deny, {
      approvalId,
      approver: APPROVER,
      reason: 'too risky'
    });

    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.status).toBe('denied');
    expect(status?.resolvedBy).toBe(APPROVER);
    expect(status?.resolvedReason).toBe('too risky');

    const trail = await auditByCorrelation(t, res.correlationId);
    expect(trail.map((r) => r.reason)).toEqual([
      'approval_required',
      'approval_denied'
    ]);
  });

  test('re-resolve guard: approve then approve again → approval_not_pending', async () => {
    const t = initConvexTest();
    const approvalId = approvalIdOf(await checkHighRiskGrant(t));
    await t.mutation(api.approvals.approve, {approvalId, approver: APPROVER});
    await expectFail(
      t.mutation(api.approvals.approve, {approvalId, approver: APPROVER}),
      'approval_not_pending'
    );
  });

  test('re-resolve guard: approve then deny → approval_not_pending', async () => {
    const t = initConvexTest();
    const approvalId = approvalIdOf(await checkHighRiskGrant(t));
    await t.mutation(api.approvals.approve, {approvalId, approver: APPROVER});
    await expectFail(
      t.mutation(api.approvals.deny, {
        approvalId,
        approver: APPROVER,
        reason: 'changed mind'
      }),
      'approval_not_pending'
    );
  });

  test('re-resolve guard: deny then approve → approval_not_pending', async () => {
    const t = initConvexTest();
    const approvalId = approvalIdOf(await checkHighRiskGrant(t));
    await t.mutation(api.approvals.deny, {
      approvalId,
      approver: APPROVER,
      reason: 'no'
    });
    await expectFail(
      t.mutation(api.approvals.approve, {approvalId, approver: APPROVER}),
      'approval_not_pending'
    );
  });

  test('empty approver → typed fail', async () => {
    const t = initConvexTest();
    const approvalId = approvalIdOf(await checkHighRiskGrant(t));
    await expectFail(
      t.mutation(api.approvals.approve, {approvalId, approver: ''}),
      'approver_required'
    );
  });
});

describe('approval expiry (lazy)', () => {
  test('past expiresAt → approve fails approval_expired; getStatus reports expired', async () => {
    const t = initConvexTest();
    const approvalId = approvalIdOf(await checkHighRiskGrant(t));

    // Force the pending approval past its expiry (test scaffolding to reach the
    // expired state — the feature itself is exercised through the public API).
    await t.run(async (ctx) => {
      await ctx.db.patch('approvals', approvalId, {
        expiresAt: Date.now() - 1000
      });
    });

    await expectFail(
      t.mutation(api.approvals.approve, {approvalId, approver: APPROVER}),
      'approval_expired'
    );

    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.status).toBe('expired');
  });

  test('checkTool with approvalTtlMs sets a future expiresAt (not yet expired)', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire_transfer',
      risk: 'high'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire_transfer',
      approvalTtlMs: 60_000
    });
    const approvalId = approvalIdOf(res);
    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.status).toBe('pending');
    expect(status?.expiresAt).not.toBeNull();
  });

  test('non-positive approvalTtlMs → typed fail (contradictory input), no rows', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire_transfer',
      risk: 'high'
    });
    await expectFail(
      t.mutation(api.enforce.checkTool, {
        subject: SUBJECT,
        tool: 'wire_transfer',
        approvalTtlMs: 0
      }),
      'invalid_ttl'
    );
    expect(await auditRows(t)).toHaveLength(0);
    expect(await approvalRows(t)).toHaveLength(0);
  });
});

describe('one-decision-row invariant (unchanged for allow/deny; one for approve)', () => {
  test('allow writes exactly one audit row', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    await t.mutation(api.enforce.checkTool, {subject: SUBJECT, tool: 'search'});
    expect(await auditRows(t)).toHaveLength(1);
  });

  test('deny writes exactly one audit row', async () => {
    const t = initConvexTest();
    await t.mutation(api.enforce.checkTool, {subject: SUBJECT, tool: 'search'});
    expect(await auditRows(t)).toHaveLength(1);
  });

  test('approve writes exactly one DECISION audit row (before resolution)', async () => {
    const t = initConvexTest();
    await checkHighRiskGrant(t);
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].reason).toBe('approval_required');
  });
});

/** Grant a tool at high risk (so checkTool routes it through the risk gate). */
async function grantHigh(t: ConvexTest, tool: string) {
  await t.mutation(api.policy.grant, {subject: SUBJECT, tool, risk: 'high'});
}

describe('single-use approval consumption (the governed re-invoke path)', () => {
  test('approve → SECOND checkTool (same args) consumes → allow; THIRD → approve again', async () => {
    const t = initConvexTest();
    await grantHigh(t, 'wire');
    const args = {amount: 500, to: 'acct-1'};

    // 1st: high-risk → approve (pending); the tool does not run.
    const first = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args,
      correlationId: 'c1'
    });
    expect(first.decision).toBe('approve');
    const approvalId = approvalIdOf(first);

    // Human approves.
    await t.mutation(api.approvals.approve, {approvalId, approver: APPROVER});

    // 2nd (SAME args): the risk step consumes the ticket → ALLOW.
    const second = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args,
      correlationId: 'c2'
    });
    expect(second.decision).toBe('allow');
    expect(second.correlationId).toBe('c2');

    // Exactly one audit row for the 2nd call: allow / approval_consumed.
    const c2 = await auditByCorrelation(t, 'c2');
    expect(c2).toHaveLength(1);
    expect(c2[0].decision).toBe('allow');
    expect(c2[0].reason).toBe('approval_consumed');

    // The ticket is now consumed (still 'approved' status, but spent).
    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.status).toBe('approved');
    expect(status?.consumedAt).not.toBeNull();

    // 3rd (SAME args): single-use — a fresh pending ticket, not another allow.
    const third = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args,
      correlationId: 'c3'
    });
    expect(third.decision).toBe('approve');
    expect(approvalIdOf(third)).not.toBe(approvalId);
  });

  test('argument binding: an approval for argsA does not authorize argsB', async () => {
    const t = initConvexTest();
    await grantHigh(t, 'wire');

    const first = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 500},
      correlationId: 'a1'
    });
    const approvalId = approvalIdOf(first);
    await t.mutation(api.approvals.approve, {approvalId, approver: APPROVER});

    // Different args → different digest → the ticket does not apply → approve.
    const other = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 999},
      correlationId: 'a2'
    });
    expect(other.decision).toBe('approve');
    expect(approvalIdOf(other)).not.toBe(approvalId);

    // The argsA ticket is untouched — no blank cheque, no arg-swap bypass.
    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.consumedAt).toBeNull();
  });

  test('revocation precedence: a revoked subject with an approved ticket denies revoked; ticket not consumed', async () => {
    const t = initConvexTest();
    await grantHigh(t, 'wire');

    const first = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 500},
      correlationId: 'r1'
    });
    const approvalId = approvalIdOf(first);
    await t.mutation(api.approvals.approve, {approvalId, approver: APPROVER});

    // Revoke the subject (global) — this short-circuits BEFORE the risk step.
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'incident'
    });

    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 500},
      correlationId: 'r2'
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('revoked');

    // The approved ticket was never consulted → still unconsumed.
    const status = await t.query(api.approvals.getStatus, {approvalId});
    expect(status?.consumedAt).toBeNull();
  });
});
