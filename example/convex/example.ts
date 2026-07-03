import {query} from './_generated/server.js';
import {components} from './_generated/api.js';
import {AgentTools} from '@kinde-oss/kinde-convex-agent-tools';
import {v} from 'convex/values';

/**
 * The component client. Construct it once with the component reference from the
 * app's generated `components` object, then call its methods. In P0 the client
 * is a shell (no decision methods yet); constructing it here proves the app can
 * resolve and wire the component.
 */
export const agentTools = new AgentTools(components.tools);

/**
 * Trivial health check proving the example app and the mounted component load.
 */
export const health = query({
  args: {},
  returns: v.string(),
  handler: async () => 'ok'
});
