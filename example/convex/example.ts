import {action, mutation, query} from './_generated/server.js';
import {api, components} from './_generated/api.js';
import {
  AgentTools,
  grantRevocationKey
} from '@kinde-oss/kinde-convex-agent-tools';
import type {ApprovalId} from '@kinde-oss/kinde-convex-agent-tools';
import {ConvexError, v} from 'convex/values';

/**
 * The component client. Construct it once with the component reference from the
 * app's generated `components` object, then call its methods.
 */
export const agentTools = new AgentTools(components.tools);

/**
 * A client wired WITH the P5 billing seam using the deny-all fake — a metered
 * call denies budget_exceeded. Used to demonstrate the budget branch.
 */
export const agentToolsWithBilling: AgentTools = new AgentTools(
  components.tools,
  {billingCheck: api.fakeBilling.billingDeny}
);

/**
 * The client the e2e narrative drives: wired with the ALLOW-all fake billing
 * seam, so the budget step is REAL (it runs and records a billingCalls row) yet
 * passes, letting the story reach the allow/deny/approve/revoke decisions the
 * COMPONENT makes. Only verifyCaller (HTTP) and billingCheck are app fakes —
 * every decision below is the real component.
 */
export const governedTools: AgentTools = new AgentTools(components.tools, {
  billingCheck: api.fakeBilling.billingAllow
});

const riskLevel = v.union(
  v.literal('low'),
  v.literal('medium'),
  v.literal('high')
);

// The flat tool-args shape the gate accepts (mirrors the component's validator).
const toolArgs = v.record(
  v.string(),
  v.union(v.string(), v.number(), v.boolean(), v.null(), v.array(v.string()))
);

const decisionResult = v.object({
  decision: v.union(
    v.literal('allow'),
    v.literal('deny'),
    v.literal('approve')
  ),
  reason: v.optional(v.string()),
  approvalId: v.optional(v.string()),
  correlationId: v.string()
});

/** Trivial health check proving the example app and mounted component load. */
export const health = query({
  args: {},
  returns: v.string(),
  handler: async () => 'ok'
});

/**
 * Drive `gate.checkTool` through the deny-all billing client — a granted, in
 * policy call still denies `budget_exceeded` at the budget step. Demonstrates
 * the billing branch end to end.
 */
export const checkToolWithBilling = mutation({
  args: {subject: v.string(), tool: v.string()},
  returns: v.object({decision: v.string(), reason: v.optional(v.string())}),
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

// --- Narrative drivers: each threads the app's subject into the PUBLIC client
// surface. The app adds no policy; the component decides everything. ---

/** Grant a tool to a subject (optionally at a risk level). */
export const grantTool = mutation({
  args: {subject: v.string(), tool: v.string(), risk: v.optional(riskLevel)},
  returns: v.null(),
  handler: async (ctx, args) => {
    await governedTools.policy.grant(ctx, args.subject, {
      tool: args.tool,
      ...(args.risk === undefined ? {} : {risk: args.risk})
    });
    return null;
  }
});

/** Grant a tool with a numeric `max` constraint on one argument. */
export const grantToolWithMaxArg = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    arg: v.string(),
    max: v.number()
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await governedTools.policy.grant(ctx, args.subject, {
      tool: args.tool,
      argumentConstraints: [{arg: args.arg, kind: 'max', value: args.max}]
    });
    return null;
  }
});

/** Set a tool's risk level (e.g. `high` to require approval). */
export const setToolRisk = mutation({
  args: {tool: v.string(), level: riskLevel},
  returns: v.null(),
  handler: async (ctx, args) => {
    await governedTools.policy.setToolRisk(ctx, args.tool, args.level);
    return null;
  }
});

/** Record that a tool's real implementation ran (fn's side effect, via db). */
export const recordToolRun = mutation({
  args: {subject: v.string(), tool: v.string()},
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert('toolRuns', {
      subject: args.subject,
      tool: args.tool,
      at: Date.now()
    });
    return null;
  }
});

/**
 * Decide + execute a tool via `gate.runTool`. This is an ACTION on purpose:
 * runTool's internal `checkTool` runs as its OWN committed mutation, so on a
 * deny/approve the decision's audit row is durably recorded BEFORE runTool
 * throws (a throw inside a single mutation would roll that row back). On allow,
 * the real tool `fn` runs (recorded via `recordToolRun`) and runTool appends the
 * completion row; on deny/approve, runTool throws and `fn` never runs.
 */
export const runGovernedTool = action({
  args: {
    subject: v.string(),
    tool: v.string(),
    args: v.optional(toolArgs),
    correlationId: v.optional(v.string())
  },
  returns: v.object({ran: v.boolean(), correlationId: v.string()}),
  handler: async (ctx, args) => {
    const out = await governedTools.gate.runTool(
      ctx,
      args.subject,
      {
        tool: args.tool,
        ...(args.args === undefined ? {} : {args: args.args}),
        ...(args.correlationId === undefined
          ? {}
          : {correlationId: args.correlationId})
      },
      async () => {
        await ctx.runMutation(api.example.recordToolRun, {
          subject: args.subject,
          tool: args.tool
        });
        return {ok: true};
      }
    );
    return {ran: true, correlationId: out.correlationId};
  }
});

/** Just the decision (no execution), via `gate.checkTool`. */
export const checkGovernedTool = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    args: v.optional(toolArgs),
    correlationId: v.optional(v.string())
  },
  returns: decisionResult,
  handler: async (ctx, args) => {
    const d = await governedTools.gate.checkTool(ctx, args.subject, {
      tool: args.tool,
      ...(args.args === undefined ? {} : {args: args.args}),
      ...(args.correlationId === undefined
        ? {}
        : {correlationId: args.correlationId})
    });
    return {
      decision: d.decision,
      ...(d.reason === undefined ? {} : {reason: d.reason}),
      ...(d.approvalId === undefined ? {} : {approvalId: d.approvalId}),
      correlationId: d.correlationId
    };
  }
});

/** Resolve a pending approval (a human reviewer authenticated by the app). */
export const approveApproval = mutation({
  args: {approvalId: v.string(), approver: v.string()},
  returns: v.null(),
  handler: async (ctx, args) => {
    await governedTools.approvals.approve(
      ctx,
      args.approvalId as ApprovalId,
      args.approver
    );
    return null;
  }
});

/**
 * Execute a tool the human APPROVED. Verifies the approval is granted, runs the
 * real tool, and appends the completion audit row tied to the approval's
 * correlation id (so the trail reads approval_required → approval_approved →
 * executed). This is the app's post-approval execution step.
 */
export const executeApproved = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    approvalId: v.string(),
    correlationId: v.string()
  },
  returns: v.object({ran: v.boolean()}),
  handler: async (ctx, args) => {
    const status = await governedTools.approvals.getStatus(
      ctx,
      args.approvalId as ApprovalId
    );
    if (status === null || status.status !== 'approved') {
      throw new ConvexError({
        code: 'not_approved',
        message: 'The approval is not granted; the tool may not run.'
      });
    }
    await ctx.db.insert('toolRuns', {
      subject: args.subject,
      tool: args.tool,
      at: Date.now()
    });
    await ctx.runMutation(components.tools.audit.recordCompletion, {
      subject: args.subject,
      tool: args.tool,
      correlationId: args.correlationId
    });
    return {ran: true};
  }
});

/** Revoke a (subject, tool) grant reactively (grant left intact). */
export const revokeSubjectTool = mutation({
  args: {subject: v.string(), tool: v.string(), reason: v.string()},
  returns: v.null(),
  handler: async (ctx, args) => {
    await governedTools.revocations.revoke(ctx, {
      targetType: 'grant',
      targetId: grantRevocationKey(args.subject, args.tool),
      reason: args.reason
    });
    return null;
  }
});

/** Lift a (subject, tool) revocation. */
export const liftSubjectTool = mutation({
  args: {subject: v.string(), tool: v.string()},
  returns: v.null(),
  handler: async (ctx, args) => {
    await governedTools.revocations.liftRevocation(ctx, {
      targetType: 'grant',
      targetId: grantRevocationKey(args.subject, args.tool)
    });
    return null;
  }
});

/** Read a subject's audit trail, newest-first (projected to the story fields). */
export const readAudit = query({
  args: {subject: v.string()},
  returns: v.array(
    v.object({
      decision: v.string(),
      reason: v.union(v.string(), v.null()),
      correlationId: v.string()
    })
  ),
  handler: async (ctx, args) => {
    const page = await governedTools.audit.query(ctx, {
      paginationOpts: {numItems: 100, cursor: null},
      subject: args.subject
    });
    return page.page.map((row) => ({
      decision: row.decision,
      reason: row.reason,
      correlationId: row.correlationId
    }));
  }
});
