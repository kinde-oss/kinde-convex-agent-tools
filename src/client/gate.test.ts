import {beforeEach, describe, expect, test, vi} from 'vitest';
import {AgentTools} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {expectFail, initConvexTest, makeRunCtx} from './setup.test.js';

const component = components.tools;

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
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
});
