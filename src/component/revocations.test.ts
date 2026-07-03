import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {grantRevocationKey} from './helpers.js';
import {expectFail, initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const SUBJECT = 'user_alice';
const TOOL = 'search';

async function auditRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('audit').collect());
}
async function grantRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('toolGrants').collect());
}
const grantTarget = grantRevocationKey(SUBJECT, TOOL);

describe('revocation overlay — reactive kill switch (public API)', () => {
  test('REACTIVITY: allow → revoke → deny → lift → allow, on identical inputs', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: TOOL});

    const before = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(before.decision).toBe('allow');

    // Revoke the (subject, tool) grant-level target — the grant itself is NOT
    // deleted (distinct from policy.revokeGrant).
    await t.mutation(api.revocations.revoke, {
      targetType: 'grant',
      targetId: grantTarget,
      reason: 'kill switch'
    });

    const during = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(during.decision).toBe('deny');
    expect(during.reason).toBe('revoked');

    // The grant was never touched — proof this is an overlay, not a deletion.
    expect(await grantRows(t)).toHaveLength(1);

    await t.mutation(api.revocations.liftRevocation, {
      targetType: 'grant',
      targetId: grantTarget
    });

    const after = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(after.decision).toBe('allow');
  });

  test('overlay BEFORE allowlist: revoked WITH a valid grant → deny revoked (not allow)', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: TOOL});
    await t.mutation(api.revocations.revoke, {
      targetType: 'grant',
      targetId: grantTarget,
      reason: 'x'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('revoked');
  });

  test('revoked wins over no_grant: revoked WITHOUT a grant → deny revoked', async () => {
    const t = initConvexTest();
    // No grant at all, but the target is revoked → overlay short-circuits, so
    // the reason is 'revoked', not 'no_grant'.
    await t.mutation(api.revocations.revoke, {
      targetType: 'grant',
      targetId: grantTarget,
      reason: 'x'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('revoked');
  });

  test('PRECEDENCE end-to-end: global outranks grant (reachable levels)', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: TOOL});

    // Both a grant-level and a global revocation are active.
    await t.mutation(api.revocations.revoke, {
      targetType: 'grant',
      targetId: grantTarget,
      reason: 'grant-level'
    });
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'global-level'
    });

    // Lifting the grant-level one leaves the global one in force → still denied.
    await t.mutation(api.revocations.liftRevocation, {
      targetType: 'grant',
      targetId: grantTarget
    });
    const stillDenied = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(stillDenied.decision).toBe('deny');
    expect(stillDenied.reason).toBe('revoked');

    // Lifting the global one too → finally allowed.
    await t.mutation(api.revocations.liftRevocation, {targetType: 'global'});
    const allowed = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL
    });
    expect(allowed.decision).toBe('allow');
  });

  test('global revocation denies an unrelated subject/tool too', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: 'user_bob', tool: 'deploy'});
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'lockdown'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: 'user_bob',
      tool: 'deploy'
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('revoked');
  });

  test('one audit row + correlationId round-trip for a revocation deny', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: TOOL});
    await t.mutation(api.revocations.revoke, {
      targetType: 'grant',
      targetId: grantTarget,
      reason: 'x'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: TOOL,
      correlationId: 'corr-rev'
    });
    expect(res.correlationId).toBe('corr-rev');
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('deny');
    expect(audits[0].reason).toBe('revoked');
    expect(audits[0].correlationId).toBe('corr-rev');
  });
});

describe('revoke / liftRevocation validation', () => {
  test("'global' with a targetId → typed fail", async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.revocations.revoke, {
        targetType: 'global',
        targetId: 'oops',
        reason: 'x'
      }),
      'invalid_target'
    );
  });

  test("'agent' without a targetId → typed fail", async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.revocations.revoke, {targetType: 'agent', reason: 'x'}),
      'invalid_target'
    );
  });

  test('re-revoking an already-active target → typed fail', async () => {
    const t = initConvexTest();
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'x'
    });
    await expectFail(
      t.mutation(api.revocations.revoke, {
        targetType: 'global',
        reason: 'again'
      }),
      'already_revoked'
    );
  });

  test('lifting a non-active target → typed fail', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.revocations.liftRevocation, {targetType: 'global'}),
      'not_revoked'
    );
  });

  test('revoke → lift → revoke reuses one row (reactivation)', async () => {
    const t = initConvexTest();
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'first'
    });
    await t.mutation(api.revocations.liftRevocation, {targetType: 'global'});
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'second'
    });
    const rows = await t.run(async (ctx) =>
      ctx.db.query('revocations').collect()
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].active).toBe(true);
    expect(rows[0].reason).toBe('second');
  });

  test('getStatus reflects active / lifted state', async () => {
    const t = initConvexTest();
    const absent = await t.query(api.revocations.getStatus, {
      targetType: 'global'
    });
    expect(absent.active).toBe(false);

    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'x',
      revokedBy: 'admin_bob'
    });
    const active = await t.query(api.revocations.getStatus, {
      targetType: 'global'
    });
    expect(active.active).toBe(true);
    expect(active.revokedBy).toBe('admin_bob');
  });
});

describe('regression: no revocations → P1/P2/P3 behavior unchanged', () => {
  test('granted tool allows; ungranted denies no_grant; high-risk approves', async () => {
    const t = initConvexTest();

    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: TOOL});
    expect(
      (await t.mutation(api.enforce.checkTool, {subject: SUBJECT, tool: TOOL}))
        .decision
    ).toBe('allow');

    const noGrant = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'unlisted'
    });
    expect(noGrant.decision).toBe('deny');
    expect(noGrant.reason).toBe('no_grant');

    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire',
      risk: 'high'
    });
    expect(
      (
        await t.mutation(api.enforce.checkTool, {
          subject: SUBJECT,
          tool: 'wire'
        })
      ).decision
    ).toBe('approve');
  });
});
