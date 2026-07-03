/// <reference types="vite/client" />
import {beforeEach, describe, expect, test, vi} from 'vitest';
import {ConvexError} from 'convex/values';
import type {Value} from 'convex/values';
import type {FunctionReference, FunctionVisibility} from 'convex/server';
import {AgentTools} from '@kinde-oss/kinde-convex-agent-tools';
import type {RunFullCtx} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';
import {governMcpTool} from '../adapters/mcp.js';
import {withKindeGovernance as withMastra} from '../adapters/mastra.js';
import {withKindeGovernance as withLangChain} from '../adapters/langchain.js';

type ConvexTest = ReturnType<typeof initConvexTest>;
type Args = Record<string, unknown>;

const SUBJECT = 'user_alice';

beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

/** Adapt a convex-test instance to the run ctx the client/adapters expect. */
function makeRunCtx(t: ConvexTest): RunFullCtx {
  const runQuery = async (
    ref: FunctionReference<'query', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.query(ref, args ?? {});
  const runMutation = async (
    ref: FunctionReference<'mutation', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.mutation(ref, args ?? {});
  const runAction = async (
    ref: FunctionReference<'action', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.action(ref, args ?? {});
  return {
    runQuery: runQuery as RunFullCtx['runQuery'],
    runMutation: runMutation as RunFullCtx['runMutation'],
    runAction: runAction as RunFullCtx['runAction']
  };
}

/** Extract the typed data of a ConvexError thrown by a rejecting promise. */
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

function setup(t: ConvexTest) {
  return {tools: new AgentTools(components.tools), ctx: makeRunCtx(t)};
}

async function grant(
  t: ConvexTest,
  tool: string,
  extra: {risk?: 'low' | 'medium' | 'high'} = {}
) {
  await t.mutation(components.tools.policy.grant, {
    subject: SUBJECT,
    tool,
    ...(extra.risk === undefined ? {} : {risk: extra.risk})
  });
}

async function auditDecisions(t: ConvexTest) {
  const page = await t.query(components.tools.audit.query, {
    paginationOpts: {numItems: 50, cursor: null}
  });
  return page.page.map((r) => ({decision: r.decision, reason: r.reason}));
}

// ---------------------------------------------------------------------------
// MCP: deny/approve → structured MCP error result; allow → real dispatch.
// ---------------------------------------------------------------------------
describe('MCP adapter transparency', () => {
  test('allow → tool dispatched, same decision as the raw gate', async () => {
    const t = initConvexTest();
    const {tools, ctx} = setup(t);
    await grant(t, 'search');

    let ran = false;
    const governed = governMcpTool<{query: string}>(
      {tools, ctx, subject: SUBJECT, toolName: 'search'},
      async (args) => {
        ran = true;
        return {content: [{type: 'text', text: `hits:${args.query}`}]};
      }
    );

    const result = await governed({query: 'hi'});
    expect(ran).toBe(true);
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toBe('hits:hi');

    // Parity: the raw gate allows the same call.
    const raw = await tools.gate.checkTool(ctx, SUBJECT, {
      tool: 'search',
      args: {query: 'hi'}
    });
    expect(raw.decision).toBe('allow');
  });

  test('deny → MCP isError with the SAME reason; tool NOT dispatched', async () => {
    const t = initConvexTest();
    const {tools, ctx} = setup(t);

    let ran = false;
    const governed = governMcpTool<{query: string}>(
      {tools, ctx, subject: SUBJECT, toolName: 'ungranted'},
      async () => {
        ran = true;
        return {content: [{type: 'text', text: 'nope'}]};
      }
    );

    const result = await governed({query: 'x'});
    expect(ran).toBe(false);
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text) as Record<
      string,
      unknown
    >;
    expect(payload.error).toBe('tool_denied');
    expect(payload.reason).toBe('no_grant');

    const raw = await tools.gate.checkTool(ctx, SUBJECT, {tool: 'ungranted'});
    expect(raw.decision).toBe('deny');
    expect(raw.reason).toBe('no_grant');
  });

  test('approve → MCP isError carrying approvalId; tool NOT dispatched', async () => {
    const t = initConvexTest();
    const {tools, ctx} = setup(t);
    await grant(t, 'wire', {risk: 'high'});

    let ran = false;
    const governed = governMcpTool(
      {tools, ctx, subject: SUBJECT, toolName: 'wire'},
      async () => {
        ran = true;
        return {content: [{type: 'text', text: 'sent'}]};
      }
    );

    const result = await governed({});
    expect(ran).toBe(false);
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0].text) as Record<
      string,
      unknown
    >;
    expect(payload.error).toBe('approval_pending');
    expect(typeof payload.approvalId).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// Mastra: deny/approve → throw typed error; allow → real execute.
// ---------------------------------------------------------------------------
describe('Mastra adapter transparency', () => {
  test('allow → execute runs; deny → throw tool_denied; approve → throw approval_pending', async () => {
    const t = initConvexTest();
    const {tools, ctx} = setup(t);
    await grant(t, 'search');
    await grant(t, 'wire', {risk: 'high'});

    let ranAllow = false;
    const allowTool = withMastra(
      {
        id: 'search',
        execute: async ({context}: {context: {query: string}}) => {
          ranAllow = true;
          return {hits: context.query};
        }
      },
      {tools, ctx, subject: SUBJECT}
    );
    const out = await allowTool.execute({context: {query: 'hi'}});
    expect(ranAllow).toBe(true);
    expect(out).toEqual({hits: 'hi'});

    // deny (ungranted)
    let ranDeny = false;
    const denyTool = withMastra(
      {
        id: 'ungranted',
        execute: async () => {
          ranDeny = true;
          return 0;
        }
      },
      {tools, ctx, subject: SUBJECT}
    );
    const denyData = await catchData(denyTool.execute({context: {}}));
    expect(ranDeny).toBe(false);
    expect(denyData.code).toBe('tool_denied');
    expect(denyData.reason).toBe('no_grant');

    // approve (high-risk)
    let ranApprove = false;
    const approveTool = withMastra(
      {
        id: 'wire',
        execute: async () => {
          ranApprove = true;
          return 'sent';
        }
      },
      {tools, ctx, subject: SUBJECT}
    );
    const approveData = await catchData(approveTool.execute({context: {}}));
    expect(ranApprove).toBe(false);
    expect(approveData.code).toBe('approval_pending');
    expect(typeof approveData.approvalId).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// LangChain: deny/approve → throw typed error; allow → real func.
// ---------------------------------------------------------------------------
describe('LangChain adapter transparency', () => {
  test('allow → func runs; deny → throw tool_denied; approve → throw approval_pending', async () => {
    const t = initConvexTest();
    const {tools, ctx} = setup(t);
    await grant(t, 'search');
    await grant(t, 'wire', {risk: 'high'});

    let ranAllow = false;
    const allowTool = withLangChain(
      {
        name: 'search',
        func: async (input: {query: string}) => {
          ranAllow = true;
          return `hits:${input.query}`;
        }
      },
      {tools, ctx, subject: SUBJECT}
    );
    expect(await allowTool.func({query: 'hi'})).toBe('hits:hi');
    expect(ranAllow).toBe(true);

    let ranDeny = false;
    const denyTool = withLangChain(
      {
        name: 'ungranted',
        func: async () => {
          ranDeny = true;
          return 'x';
        }
      },
      {tools, ctx, subject: SUBJECT}
    );
    const denyData = await catchData(denyTool.func({}));
    expect(ranDeny).toBe(false);
    expect(denyData.code).toBe('tool_denied');
    expect(denyData.reason).toBe('no_grant');

    let ranApprove = false;
    const approveTool = withLangChain(
      {
        name: 'wire',
        func: async () => {
          ranApprove = true;
          return 'sent';
        }
      },
      {tools, ctx, subject: SUBJECT}
    );
    const approveData = await catchData(approveTool.func({}));
    expect(ranApprove).toBe(false);
    expect(approveData.code).toBe('approval_pending');
    expect(typeof approveData.approvalId).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// The adapters add NO policy: the audit trail records the SAME decisions as the
// raw gate would for the same governed calls.
// ---------------------------------------------------------------------------
describe('adapters add no policy (audit parity)', () => {
  test('a governed allow/deny/approve records the same decisions as the raw gate', async () => {
    const t = initConvexTest();
    const {tools, ctx} = setup(t);
    await grant(t, 'search');
    await grant(t, 'wire', {risk: 'high'});

    // Drive one of each through the MCP adapter.
    const mcpAllow = governMcpTool(
      {tools, ctx, subject: SUBJECT, toolName: 'search'},
      async () => ({content: [{type: 'text', text: 'ok'}]})
    );
    const mcpDeny = governMcpTool(
      {tools, ctx, subject: SUBJECT, toolName: 'ungranted'},
      async () => ({content: [{type: 'text', text: 'ok'}]})
    );
    const mcpApprove = governMcpTool(
      {tools, ctx, subject: SUBJECT, toolName: 'wire'},
      async () => ({content: [{type: 'text', text: 'ok'}]})
    );
    await mcpAllow({});
    await mcpDeny({});
    await mcpApprove({});

    // Newest-first: approve (wire), deny (ungranted), allow (search).
    expect(await auditDecisions(t)).toEqual([
      {decision: 'approve', reason: 'approval_required'},
      {decision: 'deny', reason: 'no_grant'},
      {decision: 'allow', reason: 'granted'}
    ]);
  });
});
