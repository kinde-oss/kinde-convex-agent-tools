import {beforeEach, describe, expect, test, vi} from 'vitest';
import {AgentTools, grantRevocationKey} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {expectFail, initConvexTest, makeRunCtx} from './setup.test.js';

const component = components.tools;

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

describe('AgentTools client — revocations surface', () => {
  test('reactivity through the client: allow → revoke → deny → lift → allow', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    const targetId = grantRevocationKey('user_alice', 'search');

    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    expect(
      (await tools.gate.checkTool(ctx, 'user_alice', {tool: 'search'})).decision
    ).toBe('allow');

    await tools.revocations.revoke(ctx, {
      targetType: 'grant',
      targetId,
      reason: 'client kill switch'
    });
    const denied = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'search'
    });
    expect(denied.decision).toBe('deny');
    expect(denied.reason).toBe('revoked');

    await tools.revocations.liftRevocation(ctx, {
      targetType: 'grant',
      targetId
    });
    expect(
      (await tools.gate.checkTool(ctx, 'user_alice', {tool: 'search'})).decision
    ).toBe('allow');
  });

  test('client getStatus + validation fail surface through', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    await tools.revocations.revoke(ctx, {
      targetType: 'global',
      reason: 'lockdown'
    });
    const status = await tools.revocations.getStatus(ctx, {
      targetType: 'global'
    });
    expect(status.active).toBe(true);

    await expectFail(
      tools.revocations.revoke(ctx, {
        targetType: 'global',
        targetId: 'oops',
        reason: 'x'
      }),
      'invalid_target'
    );
  });
});
