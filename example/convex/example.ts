import {mutation, query} from './_generated/server.js';
import {api, components} from './_generated/api.js';
import {AgentTools} from '@kinde-oss/kinde-convex-agent-tools';
import {v} from 'convex/values';

/**
 * The component client. Construct it once with the component reference from the
 * app's generated `components` object, then call its methods.
 */
export const agentTools = new AgentTools(components.tools);

/**
 * A second client wired WITH the P5 billing seam: its `billingCheck` is a
 * FunctionReference to an app-provided mutation. `gate.checkTool` serializes it
 * to a FunctionHandle and threads it into the spine, which invokes it during the
 * budget step. (Uses the deny-all fake, so a metered call denies budget_exceeded.)
 */
export const agentToolsWithBilling: AgentTools = new AgentTools(
  components.tools,
  {billingCheck: api.fakeBilling.billingDeny}
);

/**
 * Trivial health check proving the example app and the mounted component load.
 */
export const health = query({
  args: {},
  returns: v.string(),
  handler: async () => 'ok'
});

/**
 * Drive `gate.checkTool` through the billing-wired client — proves the client
 * end-to-end: it creates the handle in this mutation's context and threads it
 * into the spine.
 */
export const checkToolWithBilling = mutation({
  args: {subject: v.string(), tool: v.string()},
  returns: v.object({
    decision: v.string(),
    reason: v.optional(v.string())
  }),
  handler: async (ctx, args) => {
    const result = await agentToolsWithBilling.gate.checkTool(
      ctx,
      args.subject,
      {tool: args.tool}
    );
    return {
      decision: result.decision,
      ...(result.reason === undefined ? {} : {reason: result.reason})
    };
  }
});
