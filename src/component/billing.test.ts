/// <reference types="vite/client" />
import {describe, expect, test} from 'vitest';
import {createFunctionHandle, makeFunctionReference} from 'convex/server';
import type {FunctionReference} from 'convex/server';
import {mutation} from './_generated/server.js';
import {v} from 'convex/values';
import {api} from './_generated/api.js';
import {expectFail, initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const billingArgs = {
  subject: v.string(),
  tool: v.string(),
  argDigest: v.string(),
  correlationId: v.string()
};

// Fake billing checks, defined as TEST-MODULE mutations so they are never
// shipped (test files are excluded from the build and from codegen) yet are
// registered by convex-test and reachable by path. They mirror an app-provided
// billing mutation: same redacted payload in, {allow, reason?} out.
export const fakeAllow = mutation({
  args: billingArgs,
  returns: v.object({allow: v.boolean()}),
  handler: async () => ({allow: true})
});
export const fakeDeny = mutation({
  args: billingArgs,
  returns: v.object({allow: v.boolean(), reason: v.optional(v.string())}),
  handler: async () => ({allow: false, reason: 'over budget'})
});
export const fakeMalformed = mutation({
  args: billingArgs,
  returns: v.object({ok: v.number()}),
  handler: async () => ({ok: 1})
});

const allowRef = makeFunctionReference<'mutation'>('billing.test:fakeAllow');
const denyRef = makeFunctionReference<'mutation'>('billing.test:fakeDeny');
const malformedRef = makeFunctionReference<'mutation'>(
  'billing.test:fakeMalformed'
);

const SUBJECT = 'user_alice';

async function handleOf(
  t: ConvexTest,
  ref: FunctionReference<'mutation'>
): Promise<string> {
  return await t.run(async () => createFunctionHandle(ref));
}
async function auditRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('audit').collect());
}
async function toolCallRows(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('toolCalls').collect());
}

describe('budget step — injected billing seam', () => {
  test('standalone: NO billingCheck → granted call allows, unchanged', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(res.decision).toBe('allow');
    expect(await auditRows(t)).toHaveLength(1);
  });

  test('billingCheck allows → call proceeds to allow (one audit row)', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      billingCheck: await handleOf(t, allowRef)
    });
    expect(res.decision).toBe('allow');
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('allow');
  });

  test('budget runs BEFORE risk: allowed-budget high-risk tool still approves', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'wire',
      risk: 'high'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'wire',
      billingCheck: await handleOf(t, allowRef)
    });
    // Billing passed, THEN the risk gate routed to approval.
    expect(res.decision).toBe('approve');
    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('approve');
  });

  test('billingCheck denies → deny budget_exceeded, exactly one audit row, correlationId round-trips', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      correlationId: 'corr-budget',
      billingCheck: await handleOf(t, denyRef)
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('budget_exceeded');
    expect(res.correlationId).toBe('corr-budget');

    const audits = await auditRows(t);
    expect(audits).toHaveLength(1);
    expect(audits[0].decision).toBe('deny');
    expect(audits[0].reason).toBe('budget_exceeded');
    expect(audits[0].correlationId).toBe('corr-budget');

    const calls = await toolCallRows(t);
    expect(calls).toHaveLength(1);
    expect(calls[0].reason).toBe('budget_exceeded');
  });

  test('malformed billing return → typed billing_check_malformed, atomic (no rows)', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    await expectFail(
      t.mutation(api.enforce.checkTool, {
        subject: SUBJECT,
        tool: 'search',
        billingCheck: await handleOf(t, malformedRef)
      }),
      'billing_check_malformed'
    );
    // A hard fail rolls the whole transaction back: nothing is recorded.
    expect(await auditRows(t)).toHaveLength(0);
    expect(await toolCallRows(t)).toHaveLength(0);
  });
});

describe('budget precedence — billing is consulted only after allowlist + args', () => {
  test('failing argument policy denies argument_denied WITHOUT consulting billing', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {
      subject: SUBJECT,
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });
    // Deny-all billing is wired; if it were consulted the reason would be
    // budget_exceeded. Getting argument_denied proves billing was NOT reached.
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 500},
      billingCheck: await handleOf(t, denyRef)
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('argument_denied');
  });

  test('ungranted call denies no_grant WITHOUT consulting billing', async () => {
    const t = initConvexTest();
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      billingCheck: await handleOf(t, denyRef)
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('no_grant');
  });

  test('revoked call denies revoked WITHOUT consulting billing', async () => {
    const t = initConvexTest();
    await t.mutation(api.policy.grant, {subject: SUBJECT, tool: 'search'});
    await t.mutation(api.revocations.revoke, {
      targetType: 'global',
      reason: 'lockdown'
    });
    const res = await t.mutation(api.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      billingCheck: await handleOf(t, denyRef)
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('revoked');
  });
});
