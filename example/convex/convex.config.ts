import {defineApp} from 'convex/server';
import {v} from 'convex/values';
import tools from '@kinde-oss/kinde-convex-agent-tools/convex.config.js';

const app = defineApp({
  env: {
    TOOLS_SIGNING_SECRET: v.string()
  }
});

app.use(tools, {
  env: {
    TOOLS_SIGNING_SECRET: app.env.TOOLS_SIGNING_SECRET
  }
});

export default app;
