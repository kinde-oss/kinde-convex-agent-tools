import type {
  FunctionArgs,
  FunctionReturnType,
  GenericActionCtx,
  GenericDataModel
} from 'convex/server';
import {ConvexError} from 'convex/values';
import type {ComponentApi} from '../component/_generated/component.js';
import {billingCheckHandle} from './billing.js';
import type {BillingCheck} from './billing.js';

export type {ComponentApi} from '../component/_generated/component.js';
export type {BillingCheck} from './billing.js';
export type {
  BillingCheckPayload,
  BillingCheckResult,
  // The plain, flat tool-argument shape the gate accepts — useful for apps and
  // adapters typing a tool's args. (Still framework-free: it is just a record of
  // JSON primitives / string arrays.)
  ToolArgs
} from '../component/validators.js';
// The app-mountable HTTP seam (client-side; see ./http.ts — the Twilio pattern).
export {registerRoutes} from './http.js';
export type {
  RegisterRoutesOptions,
  VerifyCaller,
  VerifiedCaller
} from './http.js';
// Runtime validators, re-exported so an app can build its billingCheck
// mutation with the exact shared arg/return shapes, and declare tool-args
// fields with the exact shape the gate accepts (no drifting local copies).
export {
  argsValidator as toolArgsValidator,
  billingCheckPayloadValidator,
  billingCheckResultValidator
} from '../component/validators.js';

export type RunQueryCtx = Pick<GenericActionCtx<GenericDataModel>, 'runQuery'>;
export type RunMutationCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  'runQuery' | 'runMutation'
>;
export type RunFullCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  'runQuery' | 'runMutation' | 'runAction'
>;

// The component functions' exact arg/return types, recovered from the generated
// component API so the client never re-declares (or drifts from) the validators.
type CheckToolArgs = FunctionArgs<ComponentApi['enforce']['checkTool']>;
type GrantArgs = FunctionArgs<ComponentApi['policy']['grant']>;
type RevokeGrantArgs = FunctionArgs<ComponentApi['policy']['revokeGrant']>;
type SetToolRiskArgs = FunctionArgs<ComponentApi['policy']['setToolRisk']>;
type SetToolPolicyArgs = FunctionArgs<ComponentApi['policy']['setToolPolicy']>;
type ApproveArgs = FunctionArgs<ComponentApi['approvals']['approve']>;
type DenyApprovalArgs = FunctionArgs<ComponentApi['approvals']['deny']>;
type GetStatusArgs = FunctionArgs<ComponentApi['approvals']['getStatus']>;
/** The opaque approvals id type, as accepted by the approvals methods. */
export type ApprovalId = GetStatusArgs['approvalId'];
type RevokeArgs = FunctionArgs<ComponentApi['revocations']['revoke']>;
type LiftRevocationArgs = FunctionArgs<
  ComponentApi['revocations']['liftRevocation']
>;
type RevocationStatusArgs = FunctionArgs<
  ComponentApi['revocations']['getStatus']
>;
type AuditQueryArgs = FunctionArgs<ComponentApi['audit']['query']>;

/** The machine-readable decision returned by {@link GateApi.checkTool}. */
export type GateResult = FunctionReturnType<
  ComponentApi['enforce']['checkTool']
>;
type GrantResult = FunctionReturnType<ComponentApi['policy']['grant']>;
type RevokeGrantResult = FunctionReturnType<
  ComponentApi['policy']['revokeGrant']
>;
type SetToolRiskResult = FunctionReturnType<
  ComponentApi['policy']['setToolRisk']
>;
type SetToolPolicyResult = FunctionReturnType<
  ComponentApi['policy']['setToolPolicy']
>;
type ApproveResult = FunctionReturnType<ComponentApi['approvals']['approve']>;
type DenyApprovalResult = FunctionReturnType<ComponentApi['approvals']['deny']>;
/** The status of an approval, as returned by {@link ApprovalsApi.getStatus}. */
export type ApprovalStatusResult = FunctionReturnType<
  ComponentApi['approvals']['getStatus']
>;
type RevokeResult = FunctionReturnType<ComponentApi['revocations']['revoke']>;
type LiftRevocationResult = FunctionReturnType<
  ComponentApi['revocations']['liftRevocation']
>;
/** The status of a revocation target, from {@link RevocationsApi.getStatus}. */
export type RevocationStatusResult = FunctionReturnType<
  ComponentApi['revocations']['getStatus']
>;
/** A page of audit rows, as returned by {@link AuditApi.query}. */
export type AuditQueryResult = FunctionReturnType<
  ComponentApi['audit']['query']
>;

/**
 * The result of a successful {@link GateApi.runTool}: the app function's return
 * value plus the decision's `correlationId` (so the caller can tie it to the
 * audit trail: the decision row and the `executed` completion row share it).
 */
export interface RunToolResult<TResult> {
  result: TResult;
  correlationId: string;
}

/**
 * The stable `targetId` for a `grant`-level revocation: the (subject, tool)
 * pair, encoded to match the component's scheme exactly. Use it to build the
 * `targetId` for `revocations.revoke`/`liftRevocation` at the `grant` level.
 */
export function grantRevocationKey(subject: string, tool: string): string {
  return JSON.stringify([subject, tool]);
}

/**
 * Everything about a `checkTool` call except the subject (which is positional)
 * and the internal `billingCheck` handle: the billing seam is configured ONLY
 * via {@link AgentToolsOptions.billingCheck} at construction, never per call,
 * so a caller can never smuggle an arbitrary serialized FunctionHandle through
 * the public options (see also the runtime strip in `runCheckTool`).
 */
export type CheckToolOptions = Omit<CheckToolArgs, 'subject' | 'billingCheck'>;
/** Everything about a grant except the subject (which is positional). */
export type GrantOptions = Omit<GrantArgs, 'subject'>;
/** Everything about a revoke except the subject (which is positional). */
export type RevokeGrantOptions = Omit<RevokeGrantArgs, 'subject'>;
/** Everything about a per-tool argument policy except the tool (positional). */
export type SetToolPolicyOptions = Omit<SetToolPolicyArgs, 'tool'>;

/** The decision surface of the client. */
export interface GateApi {
  /**
   * Run the deny-by-default decision spine for a tool call and return the
   * machine-readable decision. Thin pass-through to the component mutation.
   */
  checkTool(
    ctx: RunMutationCtx,
    subject: string,
    opts: CheckToolOptions
  ): Promise<GateResult>;

  /**
   * Decision + execution in one call: run `checkTool` ONCE, then act on the
   * outcome.
   * - allow → run `fn()` app-side, append the `executed` completion audit row,
   *   and return `{result, correlationId}`.
   * - deny → throw a ConvexError `{code:'tool_denied', reason, correlationId}`;
   *   `fn` never runs.
   * - approve → throw a ConvexError `{code:'approval_pending', approvalId,
   *   correlationId}`; `fn` never runs.
   *
   * `fn` is the APP's tool implementation and executes in the APP's context
   * (this is client-side orchestration) — it is never passed into a component
   * mutation. The pipeline is evaluated exactly once (a single `checkTool`).
   *
   * AUDIT CALLOUT — if `fn` THROWS after the allow decision, the error
   * propagates unchanged and NO completion row is written: the trail shows the
   * allow decision row without a matching `executed` row ("granted but not
   * completed"). This is inherent to the action model (the decision committed
   * in its own mutation; the app-side `fn` cannot be atomically rolled into
   * it). A caller that needs failure telemetry should catch the throw and
   * record its own failure event keyed by the decision's `correlationId`.
   */
  runTool<TResult>(
    ctx: RunMutationCtx,
    subject: string,
    opts: CheckToolOptions,
    fn: () => Promise<TResult>
  ): Promise<RunToolResult<TResult>>;
}

/** The read-only audit surface of the client. */
export interface AuditApi {
  /**
   * Paginated, newest-first, filterable read of the audit trail (by subject,
   * correlationId, and/or decision). Rows carry only the redacted digest.
   */
  query(ctx: RunQueryCtx, opts: AuditQueryArgs): Promise<AuditQueryResult>;
}

/** The policy-administration surface of the client. */
export interface PolicyApi {
  /** Upsert a subject-scoped grant for (subject, tool). */
  grant(
    ctx: RunMutationCtx,
    subject: string,
    opts: GrantOptions
  ): Promise<GrantResult>;
  /** Revoke the (subject, tool) grant. Typed-fails if none exists. */
  revokeGrant(
    ctx: RunMutationCtx,
    subject: string,
    opts: RevokeGrantOptions
  ): Promise<RevokeGrantResult>;
  /** Upsert the per-tool risk level, creating the policy row if absent. */
  setToolRisk(
    ctx: RunMutationCtx,
    tool: string,
    level: SetToolRiskArgs['level']
  ): Promise<SetToolRiskResult>;
  /**
   * Upsert the per-tool ARGUMENT policy: `noArgs` and/or global
   * `argumentConstraints` applying to the tool regardless of grant. Merge
   * semantics (omitted fields preserved); constraints validated like `grant`'s.
   */
  setToolPolicy(
    ctx: RunMutationCtx,
    tool: string,
    opts: SetToolPolicyOptions
  ): Promise<SetToolPolicyResult>;
}

/** The human-in-the-loop approval surface of the client. */
export interface ApprovalsApi {
  /** Approve a pending approval (the app authenticates `approver`). */
  approve(
    ctx: RunMutationCtx,
    approvalId: ApproveArgs['approvalId'],
    approver: string
  ): Promise<ApproveResult>;
  /** Deny a pending approval, recording the human's reason. */
  deny(
    ctx: RunMutationCtx,
    approvalId: DenyApprovalArgs['approvalId'],
    approver: string,
    reason: string
  ): Promise<DenyApprovalResult>;
  /** Read an approval's status (reports `expired` lazily). Read-only. */
  getStatus(
    ctx: RunQueryCtx,
    approvalId: GetStatusArgs['approvalId']
  ): Promise<ApprovalStatusResult>;
}

/**
 * The revocation kill-switch surface of the client. Distinct from
 * `policy.revokeGrant` (which DELETES a grant): revocation is a non-destructive
 * overlay that denies a target reactively while leaving its grant intact, and
 * supports levels above a single grant (agent, org, global). For a `grant`-level
 * target, build `opts.targetId` with {@link grantRevocationKey}.
 */
export interface RevocationsApi {
  /** Revoke a target (create/reactivate the overlay row). */
  revoke(ctx: RunMutationCtx, opts: RevokeArgs): Promise<RevokeResult>;
  /** Lift a revocation (deactivate the overlay row; typed-fails if not active). */
  liftRevocation(
    ctx: RunMutationCtx,
    opts: LiftRevocationArgs
  ): Promise<LiftRevocationResult>;
  /** Read whether a target is currently revoked. Read-only. */
  getStatus(
    ctx: RunQueryCtx,
    opts: RevocationStatusArgs
  ): Promise<RevocationStatusResult>;
}

/**
 * A tool call presented to the authorization layer, in framework-agnostic form.
 * The core decision API takes plain inputs like these — a subject, a tool name,
 * and plain args — NEVER a framework's request/tool object, so adapters
 * (MCP/Mastra/LangChain) can stay outside core.
 */
export interface ToolCall {
  /** The authenticated principal the agent is acting for. */
  subject: string;
  /** The tool being invoked. */
  tool: string;
  /** The tool arguments, as plain JSON-serializable data. */
  args?: Record<string, unknown>;
}

/**
 * Options for the {@link AgentTools} client. `billingCheck` is the billing
 * composition seam (P5). The AUTH seam (`verifyCaller`) is NOT here — it belongs
 * to the HTTP path only, so it lives on the app-mounted route's
 * {@link RegisterRoutesOptions}; in-Convex callers pass a trusted subject
 * directly.
 */
export interface AgentToolsOptions {
  /**
   * Optional billing seam. See {@link BillingCheck}. When set, every
   * `gate.checkTool` call is metered/gated by this mutation during the budget
   * step; a not-allowed result denies `budget_exceeded`.
   */
  billingCheck?: BillingCheck;
}

/**
 * Client for the Kinde agent tools authorization component.
 *
 * Construct it with the component reference from your app's generated
 * `components` object:
 *
 * ```ts
 * import {AgentTools} from '@kinde-oss/kinde-convex-agent-tools';
 * import {components} from './_generated/api.js';
 *
 * export const agentTools = new AgentTools(components.tools);
 * ```
 *
 * The public surface is namespaced: `gate` runs decisions and `policy`
 * administers grants/risk. Both are thin pass-throughs to component functions —
 * the app calls them from an action/mutation and threads its `ctx`. The
 * `billingCheck` seam is live (P5). The AUTH seam is the app-mounted HTTP route
 * (`registerRoutes`, the Twilio pattern: defined in client code so it runs in
 * the app's HTTP context and can call the app-supplied `verifyCaller`).
 */
export class AgentTools {
  /** Decision surface: run the deny-by-default spine for a tool call. */
  readonly gate: GateApi;
  /** Policy administration: grant/revoke tools and set per-tool risk. */
  readonly policy: PolicyApi;
  /** Human-in-the-loop: resolve and inspect approvals. */
  readonly approvals: ApprovalsApi;
  /** Revocation kill switch: reactively deny a target without deleting grants. */
  readonly revocations: RevocationsApi;
  /** Read-only, paginated audit trail. */
  readonly audit: AuditApi;

  constructor(
    public readonly component: ComponentApi,
    public readonly options: AgentToolsOptions = {}
  ) {
    // Shared by checkTool and runTool so the pipeline runs through ONE code
    // path. `billingCheckHandle` serializes the app's billingCheck reference to
    // a FunctionHandle (the SAME helper the HTTP route uses, so the two entry
    // points can never diverge on budget enforcement); it runs in the caller's
    // Convex function context, where createFunctionHandle is available.
    const runCheckTool = async (
      ctx: RunMutationCtx,
      subject: string,
      opts: CheckToolOptions
    ): Promise<GateResult> => {
      const billingCheck = await billingCheckHandle(options.billingCheck);
      // Defense in depth: `CheckToolOptions` omits `billingCheck` at the type
      // level, but a JS caller could still pass one — strip it here so the
      // budget seam can ONLY come from the constructor's AgentToolsOptions,
      // never be injected (or overridden) per call.
      const {billingCheck: _smuggled, ...sanitized} =
        opts as CheckToolOptions & {billingCheck?: unknown};
      return ctx.runMutation(component.enforce.checkTool, {
        subject,
        ...sanitized,
        ...(billingCheck === undefined ? {} : {billingCheck})
      });
    };

    this.gate = {
      checkTool: runCheckTool,
      runTool: async (ctx, subject, opts, fn) => {
        // ONE decision, then act. fn NEVER runs on deny/approve.
        const decision = await runCheckTool(ctx, subject, opts);
        if (decision.decision === 'deny') {
          throw new ConvexError({
            code: 'tool_denied',
            message: `Tool '${opts.tool}' was denied.`,
            reason: decision.reason ?? null,
            correlationId: decision.correlationId
          });
        }
        if (decision.decision === 'approve') {
          throw new ConvexError({
            code: 'approval_pending',
            message: `Tool '${opts.tool}' requires human approval before it can run.`,
            approvalId: decision.approvalId ?? null,
            correlationId: decision.correlationId
          });
        }
        // allow → run the app's tool app-side, then append the completion row.
        const result = await fn();
        await ctx.runMutation(component.audit.recordCompletion, {
          subject,
          tool: opts.tool,
          ...(opts.args === undefined ? {} : {args: opts.args}),
          correlationId: decision.correlationId
        });
        return {result, correlationId: decision.correlationId};
      }
    };
    this.policy = {
      grant: (ctx, subject, opts) =>
        ctx.runMutation(component.policy.grant, {subject, ...opts}),
      revokeGrant: (ctx, subject, opts) =>
        ctx.runMutation(component.policy.revokeGrant, {subject, ...opts}),
      setToolRisk: (ctx, tool, level) =>
        ctx.runMutation(component.policy.setToolRisk, {tool, level}),
      setToolPolicy: (ctx, tool, opts) =>
        ctx.runMutation(component.policy.setToolPolicy, {tool, ...opts})
    };
    this.approvals = {
      approve: (ctx, approvalId, approver) =>
        ctx.runMutation(component.approvals.approve, {approvalId, approver}),
      deny: (ctx, approvalId, approver, reason) =>
        ctx.runMutation(component.approvals.deny, {
          approvalId,
          approver,
          reason
        }),
      getStatus: (ctx, approvalId) =>
        ctx.runQuery(component.approvals.getStatus, {approvalId})
    };
    this.revocations = {
      revoke: (ctx, opts) =>
        ctx.runMutation(component.revocations.revoke, opts),
      liftRevocation: (ctx, opts) =>
        ctx.runMutation(component.revocations.liftRevocation, opts),
      getStatus: (ctx, opts) =>
        ctx.runQuery(component.revocations.getStatus, opts)
    };
    this.audit = {
      query: (ctx, opts) => ctx.runQuery(component.audit.query, opts)
    };
  }
}
