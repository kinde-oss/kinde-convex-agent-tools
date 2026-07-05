/// <reference types="vite/client" />
import {afterEach, beforeEach, describe, expect, test, vi} from 'vitest';
import type {ApprovalId} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;

const TOKEN = 'caller-ok';

interface DecisionBody {
  decision?: string;
  reason?: string;
  approvalId?: string;
  correlationId?: string;
  code?: string;
}

function post(
  t: ConvexTest,
  body: string,
  headers: Record<string, string> = {}
) {
  return t.fetch('/tools/check', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', ...headers},
    body
  });
}

const authed = {'X-Caller-Token': TOKEN, 'X-Subject': 'user_alice'};

async function auditRows(t: ConvexTest) {
  const page = await t.query(components.tools.audit.query, {
    paginationOpts: {numItems: 50, cursor: null}
  });
  return page.page;
}

describe('HTTP seam — POST /tools/check (app-mounted, verifyCaller-gated)', () => {
  beforeEach(() => {
    vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
    vi.stubEnv('MODE', 'test');
    vi.stubEnv('EXAMPLE_CALLER_TOKEN', TOKEN);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('happy path: valid token + granted tool → 200 allow, one audit row', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });

    const res = await post(
      t,
      JSON.stringify({tool: 'search', correlationId: 'http-1'}),
      authed
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as DecisionBody;
    expect(body.decision).toBe('allow');
    expect(body.correlationId).toBe('http-1');

    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('allow');
    expect(rows[0].correlationId).toBe('http-1');
  });

  test('auth failure: bad token → 401, pipeline NEVER runs (no audit row)', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });

    const res = await post(t, JSON.stringify({tool: 'search'}), {
      'X-Caller-Token': 'WRONG',
      'X-Subject': 'user_alice'
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as DecisionBody;
    expect(body.code).toBe('caller_unauthenticated');

    // The decision pipeline never ran: no grant lookup, no audit row.
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('auth failure: missing token → 401, no audit row', async () => {
    const t = initConvexTest();
    const res = await post(t, JSON.stringify({tool: 'search'}), {
      'X-Subject': 'user_alice'
    });
    expect(res.status).toBe(401);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('malformed body: non-JSON → 400 tool_request_malformed, no audit row', async () => {
    const t = initConvexTest();
    const res = await post(t, 'this is not json', authed);
    expect(res.status).toBe(400);
    const body = (await res.json()) as DecisionBody;
    expect(body.code).toBe('tool_request_malformed');
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('malformed body: missing required tool field → 400, no audit row', async () => {
    const t = initConvexTest();
    const res = await post(t, JSON.stringify({args: {x: 1}}), authed);
    expect(res.status).toBe(400);
    const body = (await res.json()) as DecisionBody;
    expect(body.code).toBe('tool_request_malformed');
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('denied decision through the route: ungranted → 403 deny no_grant, one audit row', async () => {
    const t = initConvexTest();
    const res = await post(
      t,
      JSON.stringify({tool: 'search', correlationId: 'http-deny'}),
      authed
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as DecisionBody;
    expect(body.decision).toBe('deny');
    expect(body.reason).toBe('no_grant');

    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('deny');
    expect(rows[0].reason).toBe('no_grant');
  });

  test('approve through the route: high-risk → 202 approve, pending approval exists', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'wire',
      risk: 'high'
    });

    const res = await post(t, JSON.stringify({tool: 'wire'}), authed);
    expect(res.status).toBe(202);
    const body = (await res.json()) as DecisionBody;
    expect(body.decision).toBe('approve');
    expect(typeof body.approvalId).toBe('string');

    // The pending approval really exists.
    if (typeof body.approvalId !== 'string') {
      throw new Error('expected an approvalId');
    }
    const status = await t.query(components.tools.approvals.getStatus, {
      approvalId: body.approvalId as ApprovalId
    });
    expect(status?.status).toBe('pending');
  });

  test('regression: in-app checkTool (no HTTP) still allows a granted tool', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });
    const decision = await t.mutation(components.tools.enforce.checkTool, {
      subject: 'user_alice',
      tool: 'search'
    });
    expect(decision.decision).toBe('allow');
  });
});

function postTo(
  t: ConvexTest,
  path: string,
  body: string,
  headers: Record<string, string> = {}
) {
  return t.fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', ...headers},
    body
  });
}

async function billingCallIds(t: ConvexTest): Promise<string[]> {
  const rows = await t.run(async (ctx) =>
    ctx.db.query('billingCalls').collect()
  );
  return rows.map((r) => r.correlationId);
}

describe('HTTP seam — uniform budget enforcement across entry points', () => {
  beforeEach(() => {
    vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
    vi.stubEnv('MODE', 'test');
    vi.stubEnv('EXAMPLE_CALLER_TOKEN', TOKEN);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('billingCheck configured: an HTTP allow records a billingCalls row (budget ran)', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });
    const res = await postTo(
      t,
      '/tools/check',
      JSON.stringify({tool: 'search', correlationId: 'http-allow'}),
      authed
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as DecisionBody).decision).toBe('allow');
    // The HTTP allow appears in billingCalls, exactly like an in-Convex allow —
    // the budget step ran identically over HTTP.
    expect(await billingCallIds(t)).toEqual(['http-allow']);
  });

  test('billingCheck denies over HTTP → 403 deny budget_exceeded, one audit row', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });
    const res = await postTo(
      t,
      '/tools-budget-deny/check',
      JSON.stringify({tool: 'search', correlationId: 'http-deny'}),
      authed
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as DecisionBody;
    expect(body.decision).toBe('deny');
    expect(body.reason).toBe('budget_exceeded');

    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('deny');
    expect(rows[0].reason).toBe('budget_exceeded');
  });

  test('auth before billing: a bad token → 401, NO billing call, NO audit row', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });
    const res = await postTo(
      t,
      '/tools/check',
      JSON.stringify({tool: 'search'}),
      {'X-Caller-Token': 'WRONG', 'X-Subject': 'user_alice'}
    );
    expect(res.status).toBe(401);
    // Billing must not run before verifyCaller.
    expect(await billingCallIds(t)).toHaveLength(0);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('typed pipeline error → 400 with its code (contradictory noArgs config)', async () => {
    const t = initConvexTest();
    // A GRANT-level constraint plus a noArgs TOOL policy is the contradictory
    // pairing the spine typed-fails at decision time (each write is valid on
    // its own — the combination is only visible when the call combines them).
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'ping',
      argumentConstraints: [{arg: 'x', kind: 'required'}]
    });
    await t.mutation(components.tools.policy.setToolPolicy, {
      tool: 'ping',
      noArgs: true
    });
    const res = await postTo(
      t,
      '/tools/check',
      JSON.stringify({tool: 'ping'}),
      authed
    );
    // A TYPED error stays a 400 carrying its machine-readable code — never 500.
    expect(res.status).toBe(400);
    expect(((await res.json()) as DecisionBody).code).toBe(
      'contradictory_constraint'
    );
  });

  test('unexpected server-side failure → 500 internal_error (billing seam crashes)', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });
    const res = await postTo(
      t,
      '/tools-billing-crash/check',
      JSON.stringify({tool: 'search'}),
      authed
    );
    // An untyped throw inside the pipeline is a SERVER failure, not a client
    // mistake: 500, not 400 — and the failed mutation left no audit row.
    expect(res.status).toBe(500);
    expect(((await res.json()) as DecisionBody).code).toBe('internal_error');
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('regression: a route with NO billingCheck skips the budget step', async () => {
    const t = initConvexTest();
    await t.mutation(components.tools.policy.grant, {
      subject: 'user_alice',
      tool: 'search'
    });
    const res = await postTo(
      t,
      '/tools-no-billing/check',
      JSON.stringify({tool: 'search', correlationId: 'http-nobilling'}),
      authed
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as DecisionBody).decision).toBe('allow');
    // No billingCheck on this route → the budget step is skipped.
    expect(await billingCallIds(t)).toHaveLength(0);
  });
});
