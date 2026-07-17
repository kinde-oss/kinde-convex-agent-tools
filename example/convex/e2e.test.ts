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
import {ConvexError} from 'convex/values';
import type {Value} from 'convex/values';
import {SignJWT, exportJWK, generateKeyPair} from 'jose';
import type {JWK} from 'jose';
import type {ApprovalId} from '@kinde-oss/kinde-convex-agent-tools';
import {api, components} from './_generated/api.js';
import {initConvexTest} from './setup.test.js';

type ConvexTest = ReturnType<typeof initConvexTest>;
type JwkRecord = Record<string, string | string[]>;

const AGENT = 'agent_007';
const SECRET = 'sk-super-secret-value-1234';

const DOMAIN = 'testco.kinde.com';
const ISSUER = `https://${DOMAIN}`;
const JWKS_URL = `${ISSUER}/.well-known/jwks`;

let signingKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let publicJwk: JwkRecord;

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
  const pair = await generateKeyPair('RS256', {extractable: true});
  signingKey = pair.privateKey;
  publicJwk = toJwkRecord(await exportJWK(pair.publicKey), 'key-main');
});

/** A valid Kinde-shaped user token for `sub`, signed by the tenant's key. */
async function mint(sub: string): Promise<string> {
  return await new SignJWT({})
    .setProtectedHeader({alg: 'RS256', kid: 'key-main'})
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setSubject(sub)
    .setExpirationTime('1h')
    .sign(signingKey);
}

/** Extract the typed data of a ConvexError thrown by a rejecting app call. */
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

async function toolRunCount(t: ConvexTest): Promise<number> {
  const rows = await t.run(async (ctx) => ctx.db.query('toolRuns').collect());
  return rows.length;
}

async function billingCorrelationIds(t: ConvexTest): Promise<string[]> {
  const rows = await t.run(async (ctx) =>
    ctx.db.query('billingCalls').collect()
  );
  return rows.map((r) => r.correlationId).sort();
}

describe('end-to-end agent governance narrative', () => {
  beforeEach(() => {
    vi.stubEnv('MODE', 'test');
    vi.stubEnv('KINDE_DOMAIN', DOMAIN);
    // The example's verifyCaller verifies the token against the tenant's
    // published keys; serve them.
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === JWKS_URL) {
          return new Response(JSON.stringify({keys: [publicJwk]}), {
            status: 200,
            headers: {'Content-Type': 'application/json'}
          });
        }
        throw new Error(`Unexpected fetch: ${url}`);
      })
    );
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('grant → deny(no_grant) → deny(argument_denied)/allow → approve→approved→executed → revoke', async () => {
    const t = initConvexTest();

    // ---- (a) GRANT + ALLOW ------------------------------------------------
    // Grant 'search' to the agent. Then exercise BOTH entry paths:
    //   • the verifyCaller-composed HTTP route (subject DERIVED from the
    //     verified token's `sub` — never from client input), and
    //   • the in-Convex client (gate.runTool).
    await t.mutation(api.example.grantTool, {subject: AGENT, tool: 'search'});

    // (a.i) HTTP: the subject is whatever the token proves, nothing else.
    const httpRes = await t.fetch('/tools/check', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${await mint(AGENT)}`
      },
      body: JSON.stringify({tool: 'search', correlationId: 'c-a-http'})
    });
    expect(httpRes.status).toBe(200);
    expect(((await httpRes.json()) as {decision: string}).decision).toBe(
      'allow'
    );

    // (a.ii) in-Convex runTool: allow → fn runs (a secret arg proves redaction).
    const run = await t.action(api.example.runGovernedTool, {
      subject: AGENT,
      tool: 'search',
      args: {q: 'hello', token: SECRET},
      correlationId: 'c-a-run'
    });
    expect(run.ran).toBe(true);

    // ---- (b) OUT-OF-ALLOWLIST → deny no_grant -----------------------------
    const denyB = await catchData(
      t.action(api.example.runGovernedTool, {
        subject: AGENT,
        tool: 'delete_account',
        correlationId: 'c-b'
      })
    );
    expect(denyB.code).toBe('tool_denied');
    expect(denyB.reason).toBe('no_grant');

    // ---- (c) ARGUMENT POLICY discriminates: over-cap deny, within allow ----
    await t.mutation(api.example.grantToolWithMaxArg, {
      subject: AGENT,
      tool: 'transfer',
      arg: 'amount',
      max: 100
    });
    const denyC = await catchData(
      t.action(api.example.runGovernedTool, {
        subject: AGENT,
        tool: 'transfer',
        args: {amount: 500},
        correlationId: 'c-c-over'
      })
    );
    expect(denyC.code).toBe('tool_denied');
    expect(denyC.reason).toBe('argument_denied');

    const okC = await t.action(api.example.runGovernedTool, {
      subject: AGENT,
      tool: 'transfer',
      args: {amount: 50},
      correlationId: 'c-c-ok'
    });
    expect(okC.ran).toBe(true);

    // ---- (d) HIGH-RISK APPROVAL: approve → approved → post-approval run ----
    await t.mutation(api.example.grantTool, {subject: AGENT, tool: 'wire'});
    await t.mutation(api.example.setToolRisk, {tool: 'wire', level: 'high'});

    const pending = await t.mutation(api.example.checkGovernedTool, {
      subject: AGENT,
      tool: 'wire',
      correlationId: 'c-d'
    });
    expect(pending.decision).toBe('approve');
    expect(typeof pending.approvalId).toBe('string');
    const approvalId = pending.approvalId;
    if (approvalId === undefined) {
      throw new Error('expected an approvalId');
    }

    // A human reviewer approves.
    await t.mutation(api.example.approveApproval, {
      approvalId,
      approver: 'human_reviewer'
    });
    const status = await t.query(components.tools.approvals.getStatus, {
      approvalId: approvalId as ApprovalId
    });
    expect(status?.status).toBe('approved');

    // The app now executes the approved tool. executeApproved re-runs the
    // decision spine LIVE: it consumes the digest-bound single-use ticket
    // (audit: approval_required → approval_approved → approval_consumed →
    // executed) rather than trusting the earlier status read.
    const approvedRun = await t.mutation(api.example.executeApproved, {
      subject: AGENT,
      tool: 'wire',
      approvalId,
      correlationId: 'c-d'
    });
    expect(approvedRun.ran).toBe(true);

    // REPLAY BLOCKED: the ticket was consumed by the run above — replaying the
    // same approval typed-fails and the tool does NOT run again.
    const replay = await catchData(
      t.mutation(api.example.executeApproved, {
        subject: AGENT,
        tool: 'wire',
        approvalId,
        correlationId: 'c-d'
      })
    );
    expect(replay.code).toBe('not_approved');

    // ---- (e) REACTIVE REVOCATION mid-run ----------------------------------
    // 'search' allowed moments ago; revoke it (grant untouched) → next call
    // denies 'revoked'. Then lift → allowed again.
    await t.mutation(api.example.revokeSubjectTool, {
      subject: AGENT,
      tool: 'search',
      reason: 'incident-42'
    });
    const revoked = await t.mutation(api.example.checkGovernedTool, {
      subject: AGENT,
      tool: 'search',
      correlationId: 'c-e'
    });
    expect(revoked.decision).toBe('deny');
    expect(revoked.reason).toBe('revoked');

    await t.mutation(api.example.liftSubjectTool, {
      subject: AGENT,
      tool: 'search'
    });
    const relifted = await t.mutation(api.example.checkGovernedTool, {
      subject: AGENT,
      tool: 'search',
      correlationId: 'c-e2'
    });
    expect(relifted.decision).toBe('allow');

    // ---- (f) THE AUDIT STORY (one coherent trail, newest-first) -----------
    const trail = await t.query(api.example.readAudit, {subject: AGENT});
    expect(trail.map((r) => [r.decision, r.reason, r.correlationId])).toEqual([
      ['allow', 'granted', 'c-e2'],
      ['deny', 'revoked', 'c-e'],
      ['allow', 'executed', 'c-d'],
      ['allow', 'approval_consumed', 'c-d'],
      ['approve', 'approval_approved', 'c-d'],
      ['approve', 'approval_required', 'c-d'],
      ['allow', 'executed', 'c-c-ok'],
      ['allow', 'granted', 'c-c-ok'],
      ['deny', 'argument_denied', 'c-c-over'],
      ['deny', 'no_grant', 'c-b'],
      ['allow', 'executed', 'c-a-run'],
      ['allow', 'granted', 'c-a-run'],
      ['allow', 'granted', 'c-a-http']
    ]);

    // Correlation ids tie each decision to its follow-on rows:
    const cd = await t.query(components.tools.audit.query, {
      paginationOpts: {numItems: 10, cursor: null},
      correlationId: 'c-d'
    });
    expect(cd.page.map((r) => r.reason)).toEqual([
      'executed',
      'approval_consumed',
      'approval_approved',
      'approval_required'
    ]);
    const cRun = await t.query(components.tools.audit.query, {
      paginationOpts: {numItems: 10, cursor: null},
      correlationId: 'c-a-run'
    });
    expect(cRun.page.map((r) => r.reason)).toEqual(['executed', 'granted']);

    // Only the allowed / approved-then-executed tools actually ran.
    expect(await toolRunCount(t)).toBe(3); // c-a-run, c-c-ok, c-d

    // The budget step was REAL: it ran on exactly the paths that reached it
    // (after allowlist + argument policy, before/at risk), and NOT on the ones
    // short-circuited earlier (no_grant, argument_denied, revoked). The HTTP
    // route is now budget-gated too, so the HTTP allow (`c-a-http`) is present
    // alongside the in-Convex allows — enforcement is uniform across entry
    // points. `c-d` appears TWICE: once for the original approval-routed check
    // and once for executeApproved's live re-check that consumed the ticket.
    expect(await billingCorrelationIds(t)).toEqual([
      'c-a-http',
      'c-a-run',
      'c-c-ok',
      'c-d',
      'c-d',
      'c-e2'
    ]);

    // Redaction: the secret never appears anywhere in the audit trail.
    const full = await t.query(components.tools.audit.query, {
      paginationOpts: {numItems: 100, cursor: null},
      subject: AGENT
    });
    for (const row of full.page) {
      expect(row.argDigest).not.toContain(SECRET);
    }
  });

  test('optional budget branch: a granted, in-policy call still denies budget_exceeded', async () => {
    const t = initConvexTest();
    await t.mutation(api.example.grantTool, {
      subject: 'agent_budget',
      tool: 'search'
    });
    // checkToolWithBilling uses the DENY-all fake billing seam.
    const result = await t.mutation(api.example.checkToolWithBilling, {
      subject: 'agent_budget',
      tool: 'search'
    });
    expect(result.decision).toBe('deny');
    expect(result.reason).toBe('budget_exceeded');
  });
});
