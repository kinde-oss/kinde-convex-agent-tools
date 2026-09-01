import {describe, expect, test} from 'vitest';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';
import type {ArgumentConstraint} from './validators.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const SUBJECT = 'user_alice';

/** Seed a subject-scoped grant directly (the grant-admin API is a later phase). */
async function grant(
  t: ConvexTest,
  opts: {
    tool: string;
    argumentConstraints?: ArgumentConstraint[] | null;
  }
): Promise<void> {
  await t.run(async (ctx) => {
    await ctx.db.insert('toolGrants', {
      subject: SUBJECT,
      agent: null,
      tool: opts.tool,
      argumentConstraints: opts.argumentConstraints ?? null,
      riskLevel: null,
      createdAt: Date.now()
    });
  });
}

/** Seed a per-tool policy directly. */
async function policy(
  t: ConvexTest,
  opts: {
    tool: string;
    noArgs?: boolean;
    argumentConstraints?: ArgumentConstraint[] | null;
  }
): Promise<void> {
  await t.run(async (ctx) => {
    await ctx.db.insert('toolPolicies', {
      tool: opts.tool,
      riskLevel: null,
      noArgs: opts.noArgs ?? false,
      argumentConstraints: opts.argumentConstraints ?? null
    });
  });
}

async function auditRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('audit').collect());
}

async function callRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('toolCalls').collect());
}

describe('enforce.checkTool', () => {
  test('deny-by-default: no grant → deny no_grant', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(result.decision).toBe('deny');
    expect(result.reason).toBe('no_grant');
  });

  test('matching grant, no constraints → allow (no reason surfaced)', async () => {
    const t = initConvexTest();
    await grant(t, {tool: 'search'});
    const result = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      args: {query: 'hello'}
    });
    expect(result.decision).toBe('allow');
    expect(result.reason).toBeUndefined();
  });

  test('numeric-cap constraint: within cap → allow, over cap → argument_denied', async () => {
    const t = initConvexTest();
    await grant(t, {
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });

    const within = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 50}
    });
    expect(within.decision).toBe('allow');

    const over = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 500}
    });
    expect(over.decision).toBe('deny');
    expect(over.reason).toBe('argument_denied');
  });

  test('deny-value constraint: forbidden value → deny, allowed value → allow', async () => {
    const t = initConvexTest();
    await grant(t, {
      tool: 'files',
      argumentConstraints: [{arg: 'action', kind: 'denyValue', value: 'delete'}]
    });

    const forbidden = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'files',
      args: {action: 'delete'}
    });
    expect(forbidden.decision).toBe('deny');
    expect(forbidden.reason).toBe('argument_denied');

    const allowed = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'files',
      args: {action: 'read'}
    });
    expect(allowed.decision).toBe('allow');
  });

  test('exactly ONE audit + one toolCalls row per decision (allow)', async () => {
    const t = initConvexTest();
    await grant(t, {tool: 'search'});
    const result = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      args: {query: 'x'}
    });

    const audits = await auditRows(t);
    const calls = await callRows(t);
    expect(audits).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(audits[0].decision).toBe('allow');
    expect(audits[0].reason).toBe('granted');
    expect(audits[0].correlationId).toBe(result.correlationId);
    expect(calls[0].correlationId).toBe(result.correlationId);
    expect(calls[0].approvalId).toBeNull();
  });

  test('exactly ONE audit row per decision (deny)', async () => {
    const t = initConvexTest();
    const result = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('deny');
    expect(audits[0].reason).toBe('no_grant');
    expect(audits[0].correlationId).toBe(result.correlationId);
  });

  test('argument digest is REDACTED: a secret arg value is not stored verbatim', async () => {
    const t = initConvexTest();
    const SECRET = 'sk-super-secret-value-1234';
    await grant(t, {tool: 'call_api'});

    await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'call_api',
      args: {apiKey: SECRET}
    });

    const audits = await auditRows(t);
    const calls = await callRows(t);
    expect(audits[0].argDigest).not.toContain(SECRET);
    expect(calls[0].argDigest).not.toContain(SECRET);
    // But the digest is present and references the arg name (schema, not secret).
    expect(audits[0].argDigest).toContain('apiKey');
  });

  test('contradictory config: no-args tool with constraints → typed fail, no audit row', async () => {
    const t = initConvexTest();
    await grant(t, {
      tool: 'ping',
      argumentConstraints: [{arg: 'x', kind: 'max', value: 1}]
    });
    await policy(t, {tool: 'ping', noArgs: true});

    await expectFail(
      t.mutation(api.enforce.checkTool, {subject: SUBJECT, tool: 'ping'}),
      'contradictory_constraint'
    );
    // A typed failure is not a decision: nothing is recorded.
    expect(await auditRows(t)).toHaveLength(0);
    expect(await callRows(t)).toHaveLength(0);
  });

  test('no coercion: a numeric-cap constraint on a non-numeric arg → typed fail', async () => {
    const t = initConvexTest();
    await grant(t, {
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });

    await expectFail(
      t.mutation(api.enforce.checkTool, {
        subject: SUBJECT,
        tool: 'transfer',
        args: {amount: 'lots'}
      }),
      'invalid_argument'
    );
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('correlationId round-trips: provided is preserved, absent is generated', async () => {
    const t = initConvexTest();
    await grant(t, {tool: 'search'});

    const withId = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      correlationId: 'corr-abc'
    });
    expect(withId.correlationId).toBe('corr-abc');

    const withoutId = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(withoutId.correlationId).not.toBe('');
    expect(withoutId.correlationId).not.toBe('corr-abc');

    const correlationIds = (await auditRows(t)).map((row) => row.correlationId);
    expect(correlationIds).toContain('corr-abc');
    expect(correlationIds).toContain(withoutId.correlationId);
  });
});
