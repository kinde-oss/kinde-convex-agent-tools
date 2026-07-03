import {beforeEach, describe, expect, test, vi} from 'vitest';
import {ConvexError} from 'convex/values';
import type {Value} from 'convex/values';
import {AgentTools} from './index.js';
import type {ApprovalId} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {initConvexTest, makeRunCtx} from './setup.test.js';

const component = components.tools;

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

/** Capture the (typed) data of a ConvexError thrown by a rejecting promise. */
async function catchData(
  promise: Promise<unknown>
): Promise<Record<string, unknown>> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ConvexError);
    const raw = (error as ConvexError<Value>).data;
    return (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<
      string,
      unknown
    >;
  }
  throw new Error('expected the call to throw a ConvexError');
}

type Ctx = ReturnType<typeof makeRunCtx>;

async function trail(ctx: Ctx, tools: AgentTools, correlationId: string) {
  const page = await tools.audit.query(ctx, {
    paginationOpts: {numItems: 50, cursor: null},
    correlationId
  });
  return page.page;
}

describe('gate.runTool — allow', () => {
  test('runs fn, appends the executed completion row, returns {result, correlationId}', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});

    let ran = false;
    const out = await tools.gate.runTool(
      ctx,
      'user_alice',
      {tool: 'search', args: {query: 'hi'}},
      async () => {
        ran = true;
        return {hits: 3};
      }
    );

    expect(ran).toBe(true);
    expect(out.result).toEqual({hits: 3});
    expect(typeof out.correlationId).toBe('string');

    // Newest-first, the trail is [executed, granted] — chronologically the
    // decision (granted) then the completion (executed).
    const rows = await trail(ctx, tools, out.correlationId);
    expect(rows.map((r) => r.reason)).toEqual(['executed', 'granted']);
    expect(rows.every((r) => r.decision === 'allow')).toBe(true);
    // Exactly ONE decision row for this call + one completion row.
    expect(rows.filter((r) => r.reason === 'granted')).toHaveLength(1);
    expect(rows.filter((r) => r.reason === 'executed')).toHaveLength(1);
  });
});

describe('gate.runTool — deny', () => {
  test('ungranted → throws tool_denied, fn does NOT run, no completion row', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);

    let ran = false;
    const data = await catchData(
      tools.gate.runTool(ctx, 'user_alice', {tool: 'search'}, async () => {
        ran = true;
        return 'nope';
      })
    );
    expect(ran).toBe(false);
    expect(data.code).toBe('tool_denied');
    expect(data.reason).toBe('no_grant');
    expect(typeof data.correlationId).toBe('string');

    const rows = await trail(ctx, tools, data.correlationId as string);
    // Only the single deny decision row — no 'executed'.
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('deny');
    expect(rows[0].reason).toBe('no_grant');
  });

  test('argument-policy fail → tool_denied carrying argument_denied', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {
      tool: 'transfer',
      argumentConstraints: [{arg: 'amount', kind: 'max', value: 100}]
    });

    let ran = false;
    const data = await catchData(
      tools.gate.runTool(
        ctx,
        'user_alice',
        {tool: 'transfer', args: {amount: 500}},
        async () => {
          ran = true;
          return 0;
        }
      )
    );
    expect(ran).toBe(false);
    expect(data.code).toBe('tool_denied');
    expect(data.reason).toBe('argument_denied');
  });
});

describe('gate.runTool — approve', () => {
  test('high-risk → throws approval_pending with approvalId, fn does NOT run, approval is pending', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'wire', risk: 'high'});

    let ran = false;
    const data = await catchData(
      tools.gate.runTool(ctx, 'user_alice', {tool: 'wire'}, async () => {
        ran = true;
        return 'sent';
      })
    );
    expect(ran).toBe(false);
    expect(data.code).toBe('approval_pending');
    expect(typeof data.approvalId).toBe('string');

    // The pending approval really exists.
    const status = await tools.approvals.getStatus(
      ctx,
      data.approvalId as ApprovalId
    );
    expect(status?.status).toBe('pending');

    // Only the single approve decision row — no 'executed'.
    const rows = await trail(ctx, tools, data.correlationId as string);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('approve');
    expect(rows[0].reason).toBe('approval_required');
  });
});
