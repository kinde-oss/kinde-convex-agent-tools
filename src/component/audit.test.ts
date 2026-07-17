import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const SUBJECT = 'user_alice';

async function auditRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('audit').collect());
}

async function executedRows(t: ConvexTest) {
  return (await auditRows(t)).filter((row) => row.reason === 'executed');
}

/** Grant `tool` to SUBJECT so a checkTool for it allows. */
async function grant(t: ConvexTest, tool: string): Promise<void> {
  await t.mutation(api.policy.grant, {subject: SUBJECT, tool});
}

describe('audit.recordCompletion — a completion must correlate to an allow', () => {
  test('allow → complete succeeds and appends exactly one executed row', async () => {
    const t = initConvexTest();
    await grant(t, 'search');
    const decision = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      args: {query: 'kinde'},
      correlationId: 'c1'
    });
    expect(decision.decision).toBe('allow');

    await t.mutation(api.audit.recordCompletion, {
      subject: SUBJECT,
      tool: 'search',
      args: {query: 'kinde'},
      correlationId: 'c1'
    });

    const executed = await executedRows(t);
    expect(executed).toHaveLength(1);
    expect(executed[0].decision).toBe('allow');
    expect(executed[0].correlationId).toBe('c1');
    // Still redacted — a completion stores no raw args.
    expect(executed[0].argDigest).not.toContain('kinde');
  });

  test('no prior decision → rejects no_matching_decision and writes nothing', async () => {
    const t = initConvexTest();
    // A fabricated execution for a call the spine never decided.
    await expectFail(
      t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'search',
        correlationId: 'never-decided'
      }),
      'no_matching_decision'
    );
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('after a DENY → rejects; the deny row is the only history', async () => {
    const t = initConvexTest();
    // No grant → deny no_grant.
    const decision = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      correlationId: 'c2'
    });
    expect(decision.decision).toBe('deny');

    await expectFail(
      t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'search',
        correlationId: 'c2'
      }),
      'no_matching_decision'
    );
    expect(await executedRows(t)).toHaveLength(0);
    expect(await auditRows(t)).toHaveLength(1);
  });

  test('after an APPROVE (pending, not yet allowed) → rejects', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire',
      risk: 'high'
    });
    const decision = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      correlationId: 'c3'
    });
    expect(decision.decision).toBe('approve');

    // An approve is not an authorization to run — a human has not resolved it.
    await expectFail(
      t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'wire',
        correlationId: 'c3'
      }),
      'no_matching_decision'
    );
    expect(await executedRows(t)).toHaveLength(0);
  });

  test('the allow must match the SUBJECT and TOOL, not just the correlation id', async () => {
    const t = initConvexTest();
    await grant(t, 'search');
    await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      correlationId: 'c4'
    });

    // Right correlation id, different subject — someone else's allow cannot
    // authorize a completion attributed to this subject.
    await expectFail(
      t.mutation(api.audit.recordCompletion, {
        subject: 'user_mallory',
        tool: 'search',
        correlationId: 'c4'
      }),
      'no_matching_decision'
    );
    // Right correlation id, different tool.
    await expectFail(
      t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'wire',
        correlationId: 'c4'
      }),
      'no_matching_decision'
    );
    expect(await executedRows(t)).toHaveLength(0);
  });

  test('double-complete is an idempotent no-op: one executed row, no throw', async () => {
    const t = initConvexTest();
    await grant(t, 'search');
    await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      correlationId: 'c5'
    });

    const complete = async () =>
      await t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'search',
        correlationId: 'c5'
      });

    await complete();
    // A replayed completion must neither throw (the tool really did run) nor
    // inflate the trail.
    await expect(complete()).resolves.toBeNull();
    expect(await executedRows(t)).toHaveLength(1);
  });

  test('a completion cannot self-certify: an executed row is not an allow decision', async () => {
    const t = initConvexTest();
    // Seed ONLY an executed-shaped row (decision 'allow', reason 'executed') —
    // the shape a forger would try to bootstrap from.
    await t.run(async (ctx) => {
      await ctx.db.insert('audit', {
        subject: SUBJECT,
        agent: null,
        tool: 'search',
        argDigest: 'v1{}',
        decision: 'allow',
        reason: 'executed',
        correlationId: 'c6',
        ts: Date.now()
      });
    });

    // The dedup path returns quietly rather than appending a second row...
    await expect(
      t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'search',
        correlationId: 'c6'
      })
    ).resolves.toBeNull();
    // ...and no new row was written on the back of the planted one.
    expect(await executedRows(t)).toHaveLength(1);

    // A DIFFERENT tool under the same correlation id finds no real allow to
    // point back at, so the planted row certifies nothing.
    await expectFail(
      t.mutation(api.audit.recordCompletion, {
        subject: SUBJECT,
        tool: 'wire',
        correlationId: 'c6'
      }),
      'no_matching_decision'
    );
  });

  test('an approval-consumed allow authorizes a completion', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire',
      risk: 'high'
    });
    const pending = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 10},
      correlationId: 'c7'
    });
    if (pending.approvalId === undefined) {
      throw new Error('expected an approvals row');
    }
    await t.mutation(api.approvals.approve, {
      approvalId: pending.approvalId,
      approver: 'admin_bob'
    });
    // Consuming the ticket allows with reason `approval_consumed` — an allow
    // reason, so it authorizes the completion just like `granted`.
    const allowed = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 10},
      correlationId: 'c8'
    });
    expect(allowed.decision).toBe('allow');

    await t.mutation(api.audit.recordCompletion, {
      subject: SUBJECT,
      tool: 'wire',
      args: {amount: 10},
      correlationId: 'c8'
    });
    expect(await executedRows(t)).toHaveLength(1);
  });
});
