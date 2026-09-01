import {beforeEach, describe, expect, test, vi} from 'vitest';
import {AgentTools} from './index.js';
import type {GateResult} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {expectFail, initConvexTest, makeRunCtx} from './setup.test.js';

const component = components.tools;

// Stub the component's env before every test. MODE is the only var it reads.
beforeEach(() => {
  vi.stubEnv('MODE', 'test');
});

/** Narrow an approve GateResult to its approvalId (no non-null assertion). */
function approvalIdOf(res: GateResult): NonNullable<GateResult['approvalId']> {
  if (res.decision !== 'approve' || res.approvalId === undefined) {
    throw new Error(`expected an approve decision, got ${res.decision}`);
  }
  return res.approvalId;
}

describe('AgentTools client — approvals surface', () => {
  test('high-risk grant → checkTool approve; approvals.approve → approved', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    await tools.policy.grant(ctx, 'user_alice', {tool: 'wire', risk: 'high'});
    const decision = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'wire'
    });
    expect(decision.decision).toBe('approve');
    const approvalId = approvalIdOf(decision);

    const pending = await tools.approvals.getStatus(ctx, approvalId);
    expect(pending?.status).toBe('pending');

    await tools.approvals.approve(ctx, approvalId, 'admin_bob');
    const resolved = await tools.approvals.getStatus(ctx, approvalId);
    expect(resolved?.status).toBe('approved');
    expect(resolved?.resolvedBy).toBe('admin_bob');
  });

  test('approvals.deny records the reason through the client', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    await tools.policy.grant(ctx, 'user_alice', {tool: 'wire', risk: 'high'});
    const decision = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'wire'
    });
    const approvalId = approvalIdOf(decision);

    await tools.approvals.deny(ctx, approvalId, 'admin_bob', 'not this time');
    const status = await tools.approvals.getStatus(ctx, approvalId);
    expect(status?.status).toBe('denied');
    expect(status?.resolvedReason).toBe('not this time');
  });

  test('re-resolving through the client surfaces the typed fail', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    await tools.policy.grant(ctx, 'user_alice', {tool: 'wire', risk: 'high'});
    const decision = await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'wire'
    });
    const approvalId = approvalIdOf(decision);

    await tools.approvals.approve(ctx, approvalId, 'admin_bob');
    await expectFail(
      tools.approvals.approve(ctx, approvalId, 'admin_bob'),
      'approval_not_pending'
    );
  });
});
