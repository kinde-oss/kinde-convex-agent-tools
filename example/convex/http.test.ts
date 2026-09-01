/// <reference types="vite/client" />
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
  vi
} from 'vitest';
import {SignJWT, exportJWK, generateKeyPair} from 'jose';
import type {JWK} from 'jose';
import type {ApprovalId} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;
type JwkRecord = Record<string, string | string[]>;
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

const DOMAIN = 'testco.kinde.com';
const ISSUER = `https://${DOMAIN}`;
const JWKS_URL = `${ISSUER}/.well-known/jwks`;
/** The audience THIS API expects — what the example's KINDE_AUDIENCE is set to. */
const AUDIENCE = 'https://tools.example.com';
/** A different API in the SAME Kinde tenant: same issuer, same signing key. */
const OTHER_AUDIENCE = 'https://some-other-api.example.com';

const SUBJECT = 'user_alice';

// `mainKey` is the tenant's real signing key (its public half is published in
// the stubbed JWKS); `rogueKey` is an attacker's key that is NOT in the JWKS —
// the two exist to prove the route trusts signatures, not claims.
let mainKey: SigningKey;
let rogueKey: SigningKey;
let mainJwk: JwkRecord;

function toJwkRecord(jwk: JWK, kid: string): JwkRecord {
  const record: JwkRecord = {kid, alg: 'RS256', use: 'sig'};
  for (const [member, value] of Object.entries(jwk)) {
    if (typeof value === 'string') {
      record[member] = value;
    } else if (
      Array.isArray(value) &&
      value.every((item): item is string => typeof item === 'string')
    ) {
      record[member] = value;
    }
  }
  return record;
}

beforeAll(async () => {
  const main = await generateKeyPair('RS256', {extractable: true});
  const rogue = await generateKeyPair('RS256', {extractable: true});
  mainKey = main.privateKey;
  rogueKey = rogue.privateKey;
  mainJwk = toJwkRecord(await exportJWK(main.publicKey), 'key-main');
});

/** Serve the tenant's published keys; anything else is an unexpected call. */
function stubKindeEndpoints() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === JWKS_URL) {
        return new Response(JSON.stringify({keys: [mainJwk]}), {
          status: 200,
          headers: {'Content-Type': 'application/json'}
        });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    })
  );
}

interface MintOptions {
  key?: SigningKey;
  sub?: string;
  expiresInSeconds?: number;
  /** Defaults to AUDIENCE — the audience this API is configured to expect. */
  audience?: string;
}

/** Mint a Kinde-shaped user token. Defaults to a VALID token for SUBJECT. */
async function mint(options: MintOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  let jwt = new SignJWT({})
    .setProtectedHeader({alg: 'RS256', kid: 'key-main'})
    .setIssuedAt(now - 60)
    .setIssuer(ISSUER)
    .setAudience(options.audience ?? AUDIENCE)
    .setExpirationTime(now + (options.expiresInSeconds ?? 3600));
  const sub = options.sub ?? SUBJECT;
  if (sub !== '') {
    jwt = jwt.setSubject(sub);
  }
  return await jwt.sign(options.key ?? mainKey);
}

async function bearer(options: MintOptions = {}): Promise<Record<string, string>> {
  return {Authorization: `Bearer ${await mint(options)}`};
}

interface DecisionBody {
  decision?: string;
  reason?: string;
  approvalId?: string;
  correlationId?: string;
  code?: string;
}

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

function post(t: ConvexTest, body: string, headers: Record<string, string> = {}) {
  return postTo(t, '/tools/check', body, headers);
}

async function auditRows(t: ConvexTest) {
  const page = await t.query(components.tools.audit.query, {
    paginationOpts: {numItems: 50, cursor: null}
  });
  return page.page;
}

async function grantSearch(t: ConvexTest, subject: string = SUBJECT) {
  await t.mutation(components.tools.policy.grant, {subject, tool: 'search'});
}

describe('HTTP seam — POST /tools/check (app-mounted, verifyCaller-gated)', () => {
  beforeEach(() => {
    vi.stubEnv('MODE', 'test');
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
    vi.stubEnv('KINDE_AUDIENCE', AUDIENCE);
    stubKindeEndpoints();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('happy path: valid token + granted tool → 200 allow, one audit row', async () => {
    const t = initConvexTest();
    await grantSearch(t);

    const res = await post(
      t,
      JSON.stringify({tool: 'search', correlationId: 'http-1'}),
      await bearer()
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as DecisionBody;
    expect(body.decision).toBe('allow');
    expect(body.correlationId).toBe('http-1');

    const rows = await auditRows(t);
    expect(rows).toHaveLength(1);
    expect(rows[0].decision).toBe('allow');
    // The decision was attributed to the token's verified `sub`.
    expect(rows[0].subject).toBe(SUBJECT);
  });

  test('a FORGED token (valid shape, wrong key) → 401, pipeline NEVER runs', async () => {
    const t = initConvexTest();
    await grantSearch(t);

    // Correct issuer, correct claims, unexpired — signed by a key that is not
    // in the tenant's JWKS. Only the signature check catches this.
    const forged = await bearer({key: rogueKey});
    const res = await post(t, JSON.stringify({tool: 'search'}), forged);
    expect(res.status).toBe(401);
    expect(((await res.json()) as DecisionBody).code).toBe(
      'caller_unauthenticated'
    );

    // The decision pipeline never ran: no grant lookup, no audit row.
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('CROSS-AUDIENCE REPLAY: a valid tenant token minted for another API → 401', async () => {
    const t = initConvexTest();
    await grantSearch(t);

    // The sharpest case in this file: everything about this token is genuine.
    // Correct issuer, signed by the tenant's REAL key (so the JWKS check
    // passes), unexpired, real `sub` — it is simply not meant for THIS API.
    // Only the audience check can tell the difference.
    const res = await post(
      t,
      JSON.stringify({tool: 'search', correlationId: 'cross-aud'}),
      await bearer({audience: OTHER_AUDIENCE})
    );
    expect(res.status).toBe(401);
    expect(((await res.json()) as DecisionBody).code).toBe(
      'caller_unauthenticated'
    );

    // Neither handler ran: no audit row (the decision pipeline never started)
    // and no billing call (the budget seam is only reached after verifyCaller).
    expect(await auditRows(t)).toHaveLength(0);
    expect(await billingCallIds(t)).toHaveLength(0);
  });

  test('FAIL CLOSED: unset KINDE_AUDIENCE rejects even a perfectly valid token', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    // A config gap must never silently downgrade verification. `jose` treats
    // `audience: undefined` as "no audience check requested" and would accept
    // the token, so the example refuses to verify at all without the config.
    vi.stubEnv('KINDE_AUDIENCE', '');

    const res = await post(
      t,
      JSON.stringify({tool: 'search'}),
      await bearer() // correct audience — it is the CONFIG that is missing
    );
    expect(res.status).toBe(401);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('a token from another issuer → 401', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    // Correct audience, so the ISSUER is the only thing wrong here.
    const alien = await new SignJWT({})
      .setProtectedHeader({alg: 'RS256', kid: 'key-main'})
      .setIssuedAt()
      .setIssuer('https://attacker.example.com')
      .setAudience(AUDIENCE)
      .setSubject(SUBJECT)
      .setExpirationTime('1h')
      .sign(mainKey);

    const res = await post(t, JSON.stringify({tool: 'search'}), {
      Authorization: `Bearer ${alien}`
    });
    expect(res.status).toBe(401);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('an EXPIRED token → 401', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await post(
      t,
      JSON.stringify({tool: 'search'}),
      await bearer({expiresInSeconds: -60})
    );
    expect(res.status).toBe(401);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('a token with no sub claim → 401 (no subject to decide against)', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await post(
      t,
      JSON.stringify({tool: 'search'}),
      await bearer({sub: ''})
    );
    expect(res.status).toBe(401);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('auth failure: missing token → 401, no audit row', async () => {
    const t = initConvexTest();
    const res = await post(t, JSON.stringify({tool: 'search'}));
    expect(res.status).toBe(401);
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('A HEADER CANNOT CHOOSE THE SUBJECT: the token wins, X-Subject is inert', async () => {
    const t = initConvexTest();
    // Only alice is granted `search`.
    await grantSearch(t, SUBJECT);

    // A caller holding alice's token, shouting that it is mallory: the decision
    // is made for the TOKEN's sub (alice), so it allows — the header is ignored.
    const asAlice = await post(
      t,
      JSON.stringify({tool: 'search', correlationId: 'hdr-1'}),
      {...(await bearer({sub: SUBJECT})), 'X-Subject': 'user_mallory'}
    );
    expect(asAlice.status).toBe(200);
    const allowRow = (await auditRows(t)).find(
      (r) => r.correlationId === 'hdr-1'
    );
    expect(allowRow?.subject).toBe(SUBJECT);

    // And the mirror: mallory's own token cannot borrow alice's grant by
    // claiming to be her in a header — decided as mallory, who has no grant.
    const asMallory = await post(
      t,
      JSON.stringify({tool: 'search', correlationId: 'hdr-2'}),
      {
        ...(await bearer({sub: 'user_mallory'})),
        'X-Subject': SUBJECT
      }
    );
    expect(asMallory.status).toBe(403);
    const denyBody = (await asMallory.json()) as DecisionBody;
    expect(denyBody.reason).toBe('no_grant');
    const denyRow = (await auditRows(t)).find(
      (r) => r.correlationId === 'hdr-2'
    );
    expect(denyRow?.subject).toBe('user_mallory');
  });

  test('malformed body: non-JSON → 400 tool_request_malformed, no audit row', async () => {
    const t = initConvexTest();
    const res = await post(t, 'this is not json', await bearer());
    expect(res.status).toBe(400);
    const body = (await res.json()) as DecisionBody;
    expect(body.code).toBe('tool_request_malformed');
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('malformed body: missing required tool field → 400, no audit row', async () => {
    const t = initConvexTest();
    const res = await post(t, JSON.stringify({args: {x: 1}}), await bearer());
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
      await bearer()
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
      subject: SUBJECT,
      tool: 'wire',
      risk: 'high'
    });

    const res = await post(t, JSON.stringify({tool: 'wire'}), await bearer());
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
    await grantSearch(t);
    const decision = await t.mutation(components.tools.enforce.checkTool, {
      subject: SUBJECT,
      tool: 'search'
    });
    expect(decision.decision).toBe('allow');
  });
});

async function billingCallIds(t: ConvexTest): Promise<string[]> {
  const rows = await t.run(async (ctx) =>
    ctx.db.query('billingCalls').collect()
  );
  return rows.map((r) => r.correlationId);
}

describe('HTTP seam — uniform budget enforcement across entry points', () => {
  beforeEach(() => {
    vi.stubEnv('MODE', 'test');
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
    vi.stubEnv('KINDE_AUDIENCE', AUDIENCE);
    stubKindeEndpoints();
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('billingCheck configured: an HTTP allow records a billingCalls row (budget ran)', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await postTo(
      t,
      '/tools/check',
      JSON.stringify({tool: 'search', correlationId: 'http-allow'}),
      await bearer()
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as DecisionBody).decision).toBe('allow');
    // The HTTP allow appears in billingCalls, exactly like an in-Convex allow —
    // the budget step ran identically over HTTP.
    expect(await billingCallIds(t)).toEqual(['http-allow']);
  });

  test('billingCheck denies over HTTP → 403 deny budget_exceeded, one audit row', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await postTo(
      t,
      '/tools-budget-deny/check',
      JSON.stringify({tool: 'search', correlationId: 'http-deny'}),
      await bearer()
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

  test('auth before billing: a forged token → 401, NO billing call, NO audit row', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await postTo(
      t,
      '/tools/check',
      JSON.stringify({tool: 'search'}),
      await bearer({key: rogueKey})
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
      subject: SUBJECT,
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
      await bearer()
    );
    // A TYPED error stays a 400 carrying its machine-readable code — never 500.
    expect(res.status).toBe(400);
    expect(((await res.json()) as DecisionBody).code).toBe(
      'contradictory_constraint'
    );
  });

  test('unexpected server-side failure → 500 internal_error (billing seam crashes)', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await postTo(
      t,
      '/tools-billing-crash/check',
      JSON.stringify({tool: 'search'}),
      await bearer()
    );
    // An untyped throw inside the pipeline is a SERVER failure, not a client
    // mistake: 500, not 400 — and the failed mutation left no audit row.
    expect(res.status).toBe(500);
    expect(((await res.json()) as DecisionBody).code).toBe('internal_error');
    expect(await auditRows(t)).toHaveLength(0);
  });

  test('regression: a route with NO billingCheck skips the budget step', async () => {
    const t = initConvexTest();
    await grantSearch(t);
    const res = await postTo(
      t,
      '/tools-no-billing/check',
      JSON.stringify({tool: 'search', correlationId: 'http-nobilling'}),
      await bearer()
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as DecisionBody).decision).toBe('allow');
    // No billingCheck on this route → the budget step is skipped.
    expect(await billingCallIds(t)).toHaveLength(0);
  });
});
