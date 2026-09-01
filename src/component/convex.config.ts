import {defineComponent} from 'convex/server';
import {v} from 'convex/values';

export default defineComponent('tools', {
  env: {
    /**
     * Operating mode. "test" relaxes external calls for local development;
     * defaults to "live". Enum-like, and validated on read (see `env.ts`).
     */
    MODE: v.optional(v.union(v.literal('test'), v.literal('live')))
  }
});
