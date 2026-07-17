import {httpRouter} from 'convex/server';
import {createRemoteJWKSet, jwtVerify} from 'jose';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-tools';
import type {VerifiedCaller} from '@kinde-oss/kinde-convex-agent-tools';
import {api, components} from './_generated/api.js';

const http = httpRouter();

/**
 * Authenticate the caller from a REAL Kinde token and return the subject the
 * decision acts for. This is the pattern to copy: the subject is DERIVED from a
 * verified signature, never read from a header.
 *
 * Why that matters here more than anywhere else: the tools component's grant
 * lookup is identity-agnostic — it asks only "does a grant exist for this
 * subject and tool?" and cannot check that the caller IS that subject. The
 * subject IS the trust decision. An earlier version of this example read
 * `X-Subject` and passed it straight through, which let any caller decide
 * against any principal's allowlist. A header can be typed by anyone; only a
 * signature proves anything.
 *
 * The hook has no Convex ctx, so it verifies against the tenant JWKS directly
 * with jose (the same approach as agent-auth's `authorizeApprover` example). In
 * a real app, prefer `@kinde-oss/kinde-convex-agent-auth`'s `verifyCaller`,
 * which additionally checks the audience, the agent registry and revocation —
 * see the README's "Composing with agent-auth".
 */
const verifyCaller = async (request: Request): Promise<VerifiedCaller> => {
  // 1. Pull the bearer token. Never a value copied out of a body or a header
  //    that names an identity — only the credential itself.
  const header = request.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ')
    ? header.slice('Bearer '.length).trim()
    : '';
  if (token === '') {
    throw new Error('Missing caller bearer token.');
  }

  // 2. Resolve the app's own Kinde domain and build the issuer + JWKS endpoint
  //    from it. Configured out-of-band; never taken from the request.
  const domain = process.env.KINDE_DOMAIN;
  if (domain === undefined || domain.length === 0) {
    throw new Error('KINDE_DOMAIN is not configured for the app.');
  }
  const issuer = `https://${domain}`;

  // 3. Verify the signature and issuer against the tenant's published keys.
  //    jose fetches and caches the JWKS; a forged token — or one signed by a key
  //    outside this tenant, or expired — throws here, and the route maps the
  //    throw to a 401 before the decision pipeline runs.
  const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks`));
  const {payload} = await jwtVerify(token, jwks, {issuer});

  // 4. The verified `sub` is the only identity we can trust. This — not a
  //    header — is what the tool decision is made against.
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new Error('The caller token has no sub claim.');
  }
  return {subject: payload.sub};
};

// Default route, budget-gated with the ALLOW-all fake billing seam: an
// HTTP-originated call runs the IDENTICAL budget step as an in-Convex
// gate.checkTool — enforcement is uniform across entry points.
registerRoutes(http, components.tools, {
  verifyCaller,
  billingCheck: api.fakeBilling.billingAllow
});

// A second mount whose billing seam DENIES — an HTTP call is denied
// `budget_exceeded`, exactly like the in-Convex budget deny.
registerRoutes(http, components.tools, {
  pathPrefix: '/tools-budget-deny',
  verifyCaller,
  billingCheck: api.fakeBilling.billingDeny
});

// A third mount with NO billingCheck — the budget step is skipped, unchanged
// from a route that never configures billing.
registerRoutes(http, components.tools, {
  pathPrefix: '/tools-no-billing',
  verifyCaller
});

// A fourth mount whose billing seam THROWS an untyped error — exercises the
// route's 500 path (an unexpected server-side failure is NOT a 400).
registerRoutes(http, components.tools, {
  pathPrefix: '/tools-billing-crash',
  verifyCaller,
  billingCheck: api.fakeBilling.billingCrash
});
export default http;
