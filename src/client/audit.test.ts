import {beforeEach, describe, expect, test, vi} from 'vitest';
import {AgentTools} from './index.js';
import {components} from '../../example/convex/_generated/api.js';
import {initConvexTest, makeRunCtx} from './setup.test.js';

const component = components.tools;

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

type Ctx = ReturnType<typeof makeRunCtx>;

async function decide(
  ctx: Ctx,
  tools: AgentTools,
  subject: string,
  tool: string,
  correlationId: string
) {
  return await tools.gate.checkTool(ctx, subject, {tool, correlationId});
}

describe('audit.query — read-only, paginated, newest-first, filterable', () => {
  test('newest-first ordering across a subject', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});

    for (const n of [1, 2, 3]) {
      await decide(ctx, tools, 'user_alice', 'search', `c${n}`);
    }
    const page = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      subject: 'user_alice'
    });
    // Newest decision first.
    expect(page.page.map((r) => r.correlationId)).toEqual(['c3', 'c2', 'c1']);
    expect(page.page.every((r) => r.subject === 'user_alice')).toBe(true);
  });

  test('filter by subject isolates that subject', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    await tools.policy.grant(ctx, 'user_bob', {tool: 'search'});
    await decide(ctx, tools, 'user_alice', 'search', 'a1');
    await decide(ctx, tools, 'user_bob', 'search', 'b1');

    const page = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      subject: 'user_bob'
    });
    expect(page.page).toHaveLength(1);
    expect(page.page[0].correlationId).toBe('b1');
  });

  test('filter by correlationId', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    await decide(ctx, tools, 'user_alice', 'search', 'x1');
    await decide(ctx, tools, 'user_alice', 'search', 'x2');

    const page = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      correlationId: 'x2'
    });
    expect(page.page).toHaveLength(1);
    expect(page.page[0].correlationId).toBe('x2');
  });

  test('filter by decision (deny only)', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    await decide(ctx, tools, 'user_alice', 'search', 'ok'); // allow
    await decide(ctx, tools, 'user_alice', 'ungranted', 'no'); // deny

    const page = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      decision: 'deny'
    });
    expect(page.page).toHaveLength(1);
    expect(page.page[0].decision).toBe('deny');
    expect(page.page[0].correlationId).toBe('no');
  });

  test('pagination: numItems + cursor walks pages with no overlap or gap', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    for (const n of [1, 2, 3, 4, 5]) {
      await decide(ctx, tools, 'user_alice', 'search', `p${n}`);
    }

    const first = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 2, cursor: null},
      subject: 'user_alice'
    });
    expect(first.page).toHaveLength(2);
    expect(first.isDone).toBe(false);
    expect(first.page.map((r) => r.correlationId)).toEqual(['p5', 'p4']);

    const second = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 2, cursor: first.continueCursor},
      subject: 'user_alice'
    });
    expect(second.page.map((r) => r.correlationId)).toEqual(['p3', 'p2']);

    const third = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 2, cursor: second.continueCursor},
      subject: 'user_alice'
    });
    expect(third.page.map((r) => r.correlationId)).toEqual(['p1']);

    // No overlap / no gap: the union is exactly the five, in order.
    const all = [...first.page, ...second.page, ...third.page].map(
      (r) => r.correlationId
    );
    expect(all).toEqual(['p5', 'p4', 'p3', 'p2', 'p1']);
  });

  test('redaction: no raw secret appears in any returned row', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    const SECRET = 'sk-super-secret-value-1234';
    await tools.policy.grant(ctx, 'user_alice', {tool: 'call_api'});
    await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'call_api',
      args: {apiKey: SECRET},
      correlationId: 'redact'
    });

    const page = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      correlationId: 'redact'
    });
    expect(page.page).toHaveLength(1);
    expect(page.page[0].argDigest).not.toContain(SECRET);
    expect(page.page[0].argDigest).toContain('apiKey');
  });
});

describe('audit.query — combined subject+decision is EXACT (no under-fill at scale)', () => {
  test('few matches among many non-matches, interleaved, small numItems → every page full of matches, no empty page before isDone', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'granted_tool'});
    await tools.policy.grant(ctx, 'user_bob', {tool: 'granted_tool'});

    // 25 alice decisions, mostly allow, with a DENY every 5th (5 denials),
    // interleaved with an unrelated other-subject decision each iteration.
    const expectedDenies: string[] = [];
    for (let i = 0; i < 25; i++) {
      if (i % 5 === 4) {
        const cid = `alice-deny-${i}`;
        // ungranted tool → deny no_grant
        await tools.gate.checkTool(ctx, 'user_alice', {
          tool: 'ungranted_tool',
          correlationId: cid
        });
        expectedDenies.push(cid);
      } else {
        await tools.gate.checkTool(ctx, 'user_alice', {
          tool: 'granted_tool',
          correlationId: `alice-allow-${i}`
        });
      }
      // Noise from another subject (both an allow and a deny) so a naive scan
      // would have to skip past them too.
      await tools.gate.checkTool(ctx, 'user_bob', {
        tool: 'granted_tool',
        correlationId: `bob-allow-${i}`
      });
      await tools.gate.checkTool(ctx, 'user_bob', {
        tool: 'ungranted_tool',
        correlationId: `bob-deny-${i}`
      });
    }

    // Newest-first: the denies in reverse insertion order.
    const expectedNewestFirst = [...expectedDenies].reverse();

    // Page through subject=alice + decision=deny with a SMALL page size.
    const collected: string[] = [];
    let cursor: string | null = null;
    let pageCount = 0;
    let sawEmptyBeforeDone = false;
    for (;;) {
      const res: Awaited<ReturnType<typeof tools.audit.query>> =
        await tools.audit.query(ctx, {
          paginationOpts: {numItems: 3, cursor},
          subject: 'user_alice',
          decision: 'deny'
        });
      pageCount += 1;
      // Every row on every page must be a matching alice+deny row.
      for (const row of res.page) {
        expect(row.subject).toBe('user_alice');
        expect(row.decision).toBe('deny');
        collected.push(row.correlationId);
      }
      if (!res.isDone && res.page.length === 0) {
        sawEmptyBeforeDone = true;
      }
      // Anti-under-fill: any non-final page is completely full of matches.
      if (!res.isDone) {
        expect(res.page).toHaveLength(3);
      }
      if (res.isDone) {
        break;
      }
      cursor = res.continueCursor;
      // Safety valve so a bug can't loop forever.
      expect(pageCount).toBeLessThan(20);
    }

    // Exactly the matching rows, in order, no missing, no duplicates.
    expect(collected).toEqual(expectedNewestFirst);
    expect(new Set(collected).size).toBe(collected.length);
    expect(collected).toHaveLength(5);
    // The regression guarantee: no empty page appeared before isDone.
    expect(sawEmptyBeforeDone).toBe(false);
  });
});

describe('audit.query — bounded correlationId + decision exception', () => {
  test('correlationId + decision returns exactly the matching subset for that call', async () => {
    const t = initConvexTest();
    const tools = new AgentTools(component);
    const ctx = makeRunCtx(t);
    await tools.policy.grant(ctx, 'user_alice', {tool: 'search'});
    await tools.gate.checkTool(ctx, 'user_alice', {
      tool: 'search',
      correlationId: 'cx'
    });

    const asAllow = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      correlationId: 'cx',
      decision: 'allow'
    });
    expect(asAllow.page).toHaveLength(1);
    expect(asAllow.page[0].correlationId).toBe('cx');

    const asDeny = await tools.audit.query(ctx, {
      paginationOpts: {numItems: 10, cursor: null},
      correlationId: 'cx',
      decision: 'deny'
    });
    expect(asDeny.page).toHaveLength(0);
  });
});
