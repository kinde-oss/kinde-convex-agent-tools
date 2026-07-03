import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const SUBJECT = 'user_alice';

async function grantRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('toolGrants').collect());
}
async function auditRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('audit').collect());
}

describe('policy admin + reactivity (public component API)', () => {
  test('reactivity: grant → allow, revokeGrant → deny for the SAME inputs', async () => {
    const t = initConvexTest();

    // No grant yet → deny.
    const before = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(before.decision).toBe('deny');
    expect(before.reason).toBe('no_grant');

    // Grant, then the SAME call is allowed.
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    const allowed = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(allowed.decision).toBe('allow');

    // Revoke, then the SAME call is denied again (the next checkTool re-queries).
    await t.mutation(api.policy.revokeGrant, {
      subject: SUBJECT,
      tool: 'search'
    });
    const after = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(after.decision).toBe('deny');
    expect(after.reason).toBe('no_grant');
  });

  test('numeric cap (min & max) end-to-end', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'transfer',
      argumentConstraints: [
        {arg: 'amount', kind: 'min', value: 10},
        {arg: 'amount', kind: 'max', value: 100}
      ]
    });

    const inRange = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 50}
    });
    expect(inRange.decision).toBe('allow');

    const tooLow = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 5}
    });
    expect(tooLow.decision).toBe('deny');
    expect(tooLow.reason).toBe('argument_denied');

    const tooHigh = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 500}
    });
    expect(tooHigh.decision).toBe('deny');
  });

  test('required-absent → deny; present → allow', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'email',
      argumentConstraints: [{arg: 'to', kind: 'required'}]
    });

    const missing = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'email',
      args: {subjectLine: 'hi'}
    });
    expect(missing.decision).toBe('deny');
    expect(missing.reason).toBe('argument_denied');

    const present = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'email',
      args: {to: 'ada@example.com'}
    });
    expect(present.decision).toBe('allow');
  });

  test('allowValues: in-set allow, out-of-set deny', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'files',
      argumentConstraints: [
        {arg: 'action', kind: 'allowValues', values: ['read', 'write']}
      ]
    });

    const ok = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'files',
      args: {action: 'read'}
    });
    expect(ok.decision).toBe('allow');

    const bad = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'files',
      args: {action: 'delete'}
    });
    expect(bad.decision).toBe('deny');
    expect(bad.reason).toBe('argument_denied');
  });

  test('denyValue: forbidden value denied end-to-end', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'files',
      argumentConstraints: [{arg: 'action', kind: 'denyValue', value: 'delete'}]
    });

    const bad = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'files',
      args: {action: 'delete'}
    });
    expect(bad.decision).toBe('deny');
    expect(bad.reason).toBe('argument_denied');
  });

  test('grant-time validation: empty allowValues → typed fail, no grant written', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.policy.grant, {
        subject: SUBJECT,
        tool: 'files',
        argumentConstraints: [{arg: 'action', kind: 'allowValues', values: []}]
      }),
      'invalid_constraint'
    );
    expect(await grantRows(t)).toHaveLength(0);
  });

  test('grant-time validation: min>max pair → typed fail, no grant written', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.policy.grant, {
        subject: SUBJECT,
        tool: 'transfer',
        argumentConstraints: [
          {arg: 'amount', kind: 'min', value: 100},
          {arg: 'amount', kind: 'max', value: 10}
        ]
      }),
      'invalid_constraint'
    );
    expect(await grantRows(t)).toHaveLength(0);
  });

  test('revokeGrant on a non-existent grant → typed fail (not a silent no-op)', async () => {
    const t = initConvexTest();
    await expectFail(
      t.mutation(api.policy.revokeGrant, {subject: SUBJECT, tool: 'ghost'}),
      'grant_not_found'
    );
  });

  test('upsert: two grants for the same (subject, tool) → one row, second wins', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 10}]
    });

    const rows = await grantRows(t);
    expect(rows).toHaveLength(1);

    // The second grant (max 10) is the one in force.
    const at50 = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 50}
    });
    expect(at50.decision).toBe('deny');
    const at5 = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 5}
    });
    expect(at5.decision).toBe('allow');
  });

  test('setToolRisk upserts one policy row', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.setToolRisk, {tool: 'transfer', level: 'high'});
    await t.mutation(api.policy.setToolRisk, {tool: 'transfer', level: 'low'});
    const rows = await t.run(async (ctx) =>
      ctx.db.query('toolPolicies').collect()
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].riskLevel).toBe('low');
  });

  test('one-audit-row invariant holds through the public path (allow & deny)', async () => {
    const t = initConvexTest();

    // Deny path.
    await t.mutation(api.enforce.checkTool, {subject: SUBJECT, tool: 'search'});
    expect(await auditRows(t)).toHaveLength(1);

    // Allow path (fresh instance to isolate the count).
    const t2 = initConvexTest();
    await t2.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    await t2.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(await auditRows(t2)).toHaveLength(1);
  });
});
