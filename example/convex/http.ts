import {httpRouter} from 'convex/server';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';

const http = httpRouter();

// Mount the tool-decision route: `POST /tools/check`. The HTTP seam REQUIRES a
// verifyCaller (there is no unauthenticated decision route), so it is supplied
// here at the app level — the component never sees it.
//
// EXAMPLE ONLY — NOT PRODUCTION AUTH. A real app MUST authenticate the caller
// against its auth provider (verify a session cookie or bearer JWT — the blessed
// default is `@kinde-oss/kinde-convex-agent-auth`'s `verifyCaller`) and return
// the authenticated subject. Here we merely map a shared-secret header to a
// subject header, closed unless `EXAMPLE_CALLER_TOKEN` is set and the token
// matches exactly. Never ship a shared-secret header check as real auth.
registerRoutes(http, components.tools, {
  verifyCaller: async (request) => {
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
    // The authenticated subject the tool decision acts for.
    const subject = request.headers.get('X-Subject');
    if (subject === null || subject.length === 0) {
      throw new Error('Missing authenticated subject.');
    }
    return {subject};
  }
});

export default http;
