import {beforeEach, describe, expect, test, vi} from 'vitest';
import {AgentTools} from './index.js';
import type {CheckToolOptions} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {expectFail, initConvexTest, makeRunCtx} from './setup.test.js';

const component = components.tools;

// Stub the component's env before every test. MODE is the only var it reads.
beforeEach(() => {
  vi.stubEnv('MODE', 'test');
});

describe('AgentTools client — public gate/policy surface', () => {
  test('policy.grant → gate.checkTool allow; revokeGrant → deny (reactivity)', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    const denied = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'search'
    });
    expect(denied.decision).toBe('deny');
    expect(denied.reason).toBe('no_grant');

    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    const allowed = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'search'
    });
    expect(allowed.decision).toBe('allow');

    await tools.policy.revokeGrant(ctx, 'user_alice', {tool: 'search'});
    const reDenied = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'search'
    });
    expect(reDenied.decision).toBe('deny');
    expect(reDenied.reason).toBe('no_grant');
  });

  test('gate.checkTool enforces argument constraints set via policy.grant', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    await tools.policy.grant(ctx, 'user_alice', {
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });

    const ok = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'transfer',
      args: {amount: 50}
    });
    expect(ok.decision).toBe('allow');

    const denied = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'transfer',
      args: {amount: 500}
    });
    expect(denied.decision).toBe('deny');
    expect(denied.reason).toBe('argument_denied');
  });

  test('policy.revokeGrant on a missing grant surfaces the typed fail', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await expectFail(
      tools.policy.revokeGrant(ctx, 'user_alice', {tool: 'ghost'}),
      'grant_not_found'
    );
  });

  test('correlationId round-trips through the client', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    const result = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'search',
      correlationId: 'corr-xyz'
    });
    expect(result.correlationId).toBe('corr-xyz');
  });

  test('policy.setToolPolicy: a GLOBAL constraint set via the client binds every grant', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    await tools.policy.grant(ctx, 'user_alice', {tool: 'transfer'});
    await tools.policy.setToolPolicy(ctx, 'transfer', {
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });

    const denied = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'transfer',
      args: {amount: 500}
    });
    expect(denied.decision).toBe('deny');
    expect(denied.reason).toBe('argument_denied');

    const ok = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'transfer',
      args: {amount: 50}
    });
    expect(ok.decision).toBe('allow');
  });
});

describe('billing seam is NOT injectable through public checkTool options', () => {
  test('a smuggled billingCheck on an UNCONFIGURED client is stripped (budget stays skipped)', async () => {
    const t = initConvexTest();
    // No billing seam configured on the client.
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'metered'});

    // `CheckToolOptions` omits billingCheck, but a JS caller can still smuggle
    // it via width subtyping (a variable with an extra property, not a fresh
    // literal). If the client forwarded it, the component would try to invoke
    // this bogus handle and throw; the correct outcome is a plain allow with
    // the budget step skipped.
    const sneaky: CheckToolOptions & {billingCheck?: string} = {
      tool: 'metered',
      billingCheck: 'function://bogus-smuggled-handle'
    };
    const result = await tools.gate.checkTool(ctx, 'user_alice', sneaky);
    expect(result.decision).toBe('allow');
  });
});
