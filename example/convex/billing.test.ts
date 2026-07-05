/// <reference types="vite/client" />
import {beforeEach, describe, expect, test, vi} from 'vitest';
import {createFunctionHandle} from 'convex/server';
import type {FunctionReference} from 'convex/server';
import {api, components} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

const SUBJECT = 'user_alice';

async function handleOf(
  t: ConvexTest,
  ref: FunctionReference<'mutation'>
): Promise<string> {
  return await t.run(async () => createFunctionHandle(ref));
}
async function billingCalls(t: ConvexTest) {
  return await t.run(async (ctx) => ctx.db.query('billingCalls').collect());
}

describe('billing seam — real invocation counter (example app context)', () => {
  test('configured billing is invoked exactly once for a metered call', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: SUBJECT,
      tool: 'search'
    });
    const res = await t.mutation(components.tools.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      billingCheck: await handleOf(t, api.fakeBilling.billingAllow)
    });
    expect(res.decision).toBe('allow');
    expect(await billingCalls(t)).toHaveLength(1);
  });

  test('billing is NOT invoked when the call short-circuits earlier', async () => {
    const t = initConvexTest();
    const deny = await handleOf(t, api.fakeBilling.billingDeny);

    // ungranted → no_grant, billing untouched.
    await t.mutation(components.tools.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      billingCheck: deny
    });
    // argument policy fail → argument_denied, billing untouched.
    await t.mutation(components.tools.policy.grant, {
      subject: SUBJECT,
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });
    await t.mutation(components.tools.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'transfer',
      args: {amount: 500},
      billingCheck: deny
    });
    // revoked → revoked, billing untouched.
    await t.mutation(components.tools.policy.grant, {
      subject: SUBJECT,
      tool: 'search'
    });
    await t.mutation(components.tools.revocations.revoke, {
      targetType: 'global',
      reason: 'lockdown'
    });
    await t.mutation(components.tools.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search',
      billingCheck: deny
    });

    // The fake records every invocation — it was never called.
    expect(await billingCalls(t)).toHaveLength(0);
  });

  test('the payload carries the REDACTED digest, never the raw secret', async () => {
    const t = initConvexTest();
    const SECRET = 'sk-super-secret-value-1234';
    await t.mutation(components.tools.policy.grant, {
      subject: SUBJECT,
      tool: 'call_api'
    });
    await t.mutation(components.tools.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'call_api',
      args: {apiKey: SECRET},
      billingCheck: await handleOf(t, api.fakeBilling.billingAllow)
    });
    const calls = await billingCalls(t);
    expect(calls).toHaveLength(1);
    expect(calls[0].argDigest).not.toContain(SECRET);
    // The digest references the arg NAME (schema, not a secret).
    expect(calls[0].argDigest).toContain('apiKey');
  });
});

describe('billing seam — client wiring (gate.checkTool threads the reference)', () => {
  test('a billing-configured client denies budget_exceeded end to end', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: SUBJECT,
      tool: 'search'
    });
    // checkToolWithBilling constructs a client with billingCheck: billingDeny
    // and calls gate.checkTool, which creates the handle and threads it.
    const res = await t.mutation(api.example.checkToolWithBilling, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('budget_exceeded');
    expect(await billingCalls(t)).toHaveLength(1);
  });

  test('a smuggled billingCheck in public options CANNOT override the configured seam', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: SUBJECT,
      tool: 'search'
    });
    // checkToolWithSmuggledBilling smuggles a REAL handle to the ALLOW-all fake
    // through gate.checkTool's options on a client configured with the DENY-all
    // seam. The client must strip it: the configured seam still denies.
    const res = await t.mutation(api.example.checkToolWithSmuggledBilling, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(res.decision).toBe('deny');
    expect(res.reason).toBe('budget_exceeded');
    // Exactly ONE billing invocation — the configured deny seam. The smuggled
    // allow handle was never called (it would have recorded a second row and
    // flipped the decision to allow).
    const calls = await billingCalls(t);
    expect(calls).toHaveLength(1);
  });
});
