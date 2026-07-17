import {defineApp} from 'convex/server';
import tools from '@kinde-oss/kinde-convex-agent-tools/convex.config.js';

const app = defineApp();

// The component declares no required env of its own (only an optional MODE), so
// mounting it needs nothing threaded through.
app.use(tools);

export default app;
