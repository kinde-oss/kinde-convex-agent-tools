import {action, mutation, query} from './_generated/server.js';
import {api, components} from './_generated/api.js';
import {createFunctionHandle} from 'convex/server';
import {
  AgentTools,
  grantRevocationKey,
  toolArgsValidator
} from '@kinde-oss/kinde-convex-agent-tools';
import type {
  ApprovalId,
  CheckToolOptions
} from '@kinde-oss/kinde-convex-agent-tools';
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

// The flat tool-args shape the gate accepts — the PACKAGE's own validator, so
// the app's declared shape can never drift from what the component enforces.
const toolArgs = toolArgsValidator;

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
// surface. The app adds no policy; the component decides everything.
//
// EXAMPLE ONLY — INSECURE AS WRITTEN. Every function below takes `subject` (and,
// for approvals, `approver`) as a plain client-supplied argument, so any caller
// can name any identity. That keeps each function's intent readable, and it is
// exactly what a real app must NOT do. See the README's "Security model" and
// "Composing with agent-auth" sections for the wrapping each one needs. ---

/**
 * Grant a tool to a subject (optionally at a risk level).
 *
 * EXAMPLE ONLY — INSECURE AS WRITTEN. This is an ADMIN function that WIDENS
 * authority: it writes the allowlist row that turns a `no_grant` deny into an
 * allow. Exposed as a public mutation taking a client-supplied `subject`, it
 * lets any caller grant any tool to anyone — including themselves. In
 * production this MUST be wrapped behind an authenticated ADMIN session, and
 * `subject` must name the principal the admin is administering, never come from
 * the caller's own request. See the README's "Security model" (point 2).
 */
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

/**
 * Grant a tool with a numeric `max` constraint on one argument.
 *
 * EXAMPLE ONLY — INSECURE AS WRITTEN. Same admin/widening surface as
 * `grantTool`, and sharper: the caller also chooses the constraint. A caller who
 * can call this picks their own spending cap (`max: 1_000_000`), which is the
 * limit meant to bind them. Wrap behind an authenticated ADMIN session; never
 * let the constrained party supply the constraint. See the README's "Security
 * model" (point 2).
 */
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

/**
 * Just the decision (no execution), via `gate.checkTool`.
 *
 * EXAMPLE ONLY — INSECURE AS WRITTEN. This is the AGENT-FACING shape, and it
 * commits the exact mistake the README calls out: it takes `subject` from client
 * input. The grant lookup is identity-agnostic, so THE SUBJECT IS THE TRUST
 * DECISION — a caller passing `subject: 'user_admin'` gets decided against the
 * admin's allowlist, and the audit row will faithfully record the admin as the
 * actor. In production, derive the subject from a verified token
 * (`agentAuth.verifyCaller(ctx, token)` → `caller.subject`) and pass THAT in;
 * the endpoint should take a token and a tool, never a subject. See the README's
 * "Security model" (point 3) and "Composing with agent-auth".
 */
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

/**
 * Resolve a pending approval (a human reviewer authenticated by the app).
 *
 * EXAMPLE ONLY — INSECURE AS WRITTEN. `approver` is a TRUSTED STRING the
 * component stores verbatim as the record of who authorized a high-risk call,
 * and here it arrives straight from client input — so any caller can approve any
 * pending call and sign it with any name they like, including an agent approving
 * its own wire transfer as "admin_bob". The human-in-the-loop gate is only as
 * real as this identity. In production, extract `approver` from a VERIFIED HUMAN
 * SESSION (e.g. a Kinde user access token, as agent-auth's `authorizeApprover`
 * hook does — see `http.ts` in this example) and confirm that subject is
 * actually an authorized approver. Never read it from a body or header. See the
 * README's "Security model" (point 4).
 */
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
 * Execute a tool the human APPROVED. This does NOT trust a stale status read:
 * after a quick typed pre-check that the named approval is `approved` and not
 * yet consumed, the decision is re-made LIVE through `gate.checkTool`, which
 * re-checks revocation, the allowlist, argument policy and budget NOW, and
 * atomically CONSUMES the digest-bound single-use ticket in the same
 * transaction as the run. That closes every replay/rebind hole:
 * - replay: the ticket is consumed on first execution (consumedAt set) — a
 *   second call typed-fails `not_approved`;
 * - wrong run: the ticket is keyed to subject+tool+argDigest, so a different
 *   subject, tool, or args finds no ticket and typed-fails;
 * - revoked-since-approval: revocation short-circuits the spine → typed fail.
 * On success it runs the real tool and appends the completion audit row tied to
 * the approval's correlation id (trail: approval_required → approval_approved →
 * approval_consumed → executed).
 */
export const executeApproved = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    args: v.optional(toolArgs),
    approvalId: v.string(),
    correlationId: v.string()
  },
  returns: v.object({ran: v.boolean()}),
  handler: async (ctx, args) => {
    // Typed pre-check for a clear error: the NAMED approval must be approved
    // and still unconsumed (getStatus reflects consumedAt).
    const status = await governedTools.approvals.getStatus(
      ctx,
      args.approvalId as ApprovalId
    );
    if (
      status === null ||
      status.status !== 'approved' ||
      status.consumedAt !== null
    ) {
      throw new ConvexError({
        code: 'not_approved',
        message:
          'The approval is not granted (or already used); the tool may not run.'
      });
    }
    // The REAL guard: re-run the decision spine live. Only an `allow` — which,
    // for a high-risk tool, means the matching ticket was just consumed — lets
    // the tool run; anything else (revoked, re-pended, denied) refuses.
    const decision = await governedTools.gate.checkTool(ctx, args.subject, {
      tool: args.tool,
      ...(args.args === undefined ? {} : {args: args.args}),
      correlationId: args.correlationId
    });
    if (decision.decision !== 'allow') {
      throw new ConvexError({
        code: 'not_approved',
        message:
          'The live decision did not allow this run; the tool may not run.'
      });
    }
    await ctx.db.insert('toolRuns', {
      subject: args.subject,
      tool: args.tool,
      at: Date.now()
    });
    // Thread the SAME args the decision was made with. `recordCompletion`
    // validates the completion against the decision row's argDigest, so a
    // completion that omitted them would describe a different call and be
    // refused — rightly: the executed row must name the args that actually ran.
    await ctx.runMutation(components.tools.audit.recordCompletion, {
      subject: args.subject,
      tool: args.tool,
      ...(args.args === undefined ? {} : {args: args.args}),
      correlationId: args.correlationId
    });
    return {ran: true};
  }
});

/**
 * ADVERSARIAL TEST SUPPORT — attempts to smuggle a `billingCheck` handle
 * through `gate.checkTool`'s public options. The client must IGNORE it: the
 * billing seam comes ONLY from the AgentTools constructor options. This client
 * is configured with the DENY-all seam, and the smuggled handle is the
 * ALLOW-all fake — if the smuggle worked the call would allow; the correct
 * outcome is a `budget_exceeded` deny from the CONFIGURED seam.
 */
export const checkToolWithSmuggledBilling = mutation({
  args: {subject: v.string(), tool: v.string()},
  returns: v.object({decision: v.string(), reason: v.optional(v.string())}),
  handler: async (ctx, args) => {
    const smuggled = await createFunctionHandle(api.fakeBilling.billingAllow);
    // Not a fresh object literal at the call site, so excess-property checks
    // don't apply — exactly how a JS caller could smuggle the field.
    const sneaky: CheckToolOptions & {billingCheck?: string} = {
      tool: args.tool,
      billingCheck: smuggled
    };
    const result = await agentToolsWithBilling.gate.checkTool(
      ctx,
      args.subject,
      sneaky
    );
    return {
      decision: result.decision,
      ...(result.reason === undefined ? {} : {reason: result.reason})
    };
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
