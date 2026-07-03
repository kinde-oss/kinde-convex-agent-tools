import {httpRouter} from 'convex/server';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-tools';
import {api, components} from './_generated/api.js';

const http = httpRouter();

// EXAMPLE ONLY — NOT PRODUCTION AUTH. A real app MUST authenticate the caller
// against its auth provider (verify a session cookie or bearer JWT — the blessed
// default is `@kinde-oss/kinde-convex-agent-auth`'s `verifyCaller`) and return
// the authenticated subject. Here we merely map a shared-secret header to a
// subject header, closed unless `EXAMPLE_CALLER_TOKEN` is set and the token
// matches exactly. Never ship a shared-secret header check as real auth.
const verifyCaller = async (request: Request): Promise<{subject: string}> => {
  const expected = process.env.EXAMPLE_CALLER_TOKEN;
  const token = request.headers.get('X-Caller-Token');
  if (
    expected === undefined ||
    expected.length === 0 ||
    token === null ||
    token !== expected
  ) {
    throw new Error('The caller could not be authenticated.');
  }
  const subject = request.headers.get('X-Subject');
  if (subject === null || subject.length === 0) {
    throw new Error('Missing authenticated subject.');
  }
  return {subject};
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

export default http;
