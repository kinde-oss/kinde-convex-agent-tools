import {defineComponent} from 'convex/server';
import {v} from 'convex/values';

export default defineComponent('tools', {
  env: {
    /**
     * Secret used to HMAC-sign tool-call authorizations (mandates/approvals).
     * Required. Only the NAME is declared here; set the value out-of-band with
     * `npx convex env set TOOLS_SIGNING_SECRET <secret>` — never hardcode it.
     */
    TOOLS_SIGNING_SECRET: v.string(),
    /**
     * Operating mode. "test" relaxes external calls for local development;
     * defaults to "live". Enum-like, and validated on read (see `env.ts`).
     */
    MODE: v.optional(v.union(v.literal('test'), v.literal('live')))
  }
});
