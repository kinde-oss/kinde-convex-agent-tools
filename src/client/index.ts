import type {
  FunctionArgs,
  FunctionReturnType,
  GenericActionCtx,
  GenericDataModel
} from 'convex/server';
import type {ComponentApi} from '../component/_generated/component.js';

export type {ComponentApi} from '../component/_generated/component.js';

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
type ApproveArgs = FunctionArgs<ComponentApi['approvals']['approve']>;
type DenyApprovalArgs = FunctionArgs<ComponentApi['approvals']['deny']>;
type GetStatusArgs = FunctionArgs<ComponentApi['approvals']['getStatus']>;
type RevokeArgs = FunctionArgs<ComponentApi['revocations']['revoke']>;
type LiftRevocationArgs = FunctionArgs<
  ComponentApi['revocations']['liftRevocation']
>;
type RevocationStatusArgs = FunctionArgs<
  ComponentApi['revocations']['getStatus']
>;

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

/**
 * The stable `targetId` for a `grant`-level revocation: the (subject, tool)
 * pair, encoded to match the component's scheme exactly. Use it to build the
 * `targetId` for `revocations.revoke`/`liftRevocation` at the `grant` level.
 */
export function grantRevocationKey(subject: string, tool: string): string {
  return JSON.stringify([subject, tool]);
}

/** Everything about a `checkTool` call except the subject (which is positional). */
export type CheckToolOptions = Omit<CheckToolArgs, 'subject'>;
/** Everything about a grant except the subject (which is positional). */
export type GrantOptions = Omit<GrantArgs, 'subject'>;
/** Everything about a revoke except the subject (which is positional). */
export type RevokeGrantOptions = Omit<RevokeGrantArgs, 'subject'>;

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
 * Caller-authentication seam. App-supplied: authenticate a direct/cross-app
 * caller and return the proven caller identity (throw to reject). The component
 * composes with auth through this slot + a plain subject; it imports no auth
 * package. STUBBED IN P0 — accepted and typed on {@link AgentToolsOptions}, not
 * yet consulted by any code path.
 */
export type VerifyCaller = (request: Request) => Promise<unknown>;

/** The outcome of a billing check for a tool call. */
export interface BillingCheckResult {
  /** Whether billing permits the call. */
  allow: boolean;
  /** Optional machine-readable reason when `allow` is false. */
  reason?: string;
}

/**
 * Billing seam. App-supplied: decide whether billing permits a tool call. The
 * component composes with billing through this slot and imports no billing
 * package. STUBBED IN P0 — accepted and typed on {@link AgentToolsOptions}, not
 * yet consulted by any code path.
 */
export type BillingCheck = (call: ToolCall) => Promise<BillingCheckResult>;

/**
 * Options for the {@link AgentTools} client.
 *
 * The `verifyCaller` and `billingCheck` slots are the composition seams for auth
 * and billing respectively: both are optional, app-supplied, and — in P0 —
 * typed and accepted but unused. `signingSecretEnvVar` names the env var the
 * component reads its HMAC signing secret from.
 */
export interface AgentToolsOptions {
  /**
   * Name of the env var holding the HMAC signing secret the component reads.
   * Defaults to `TOOLS_SIGNING_SECRET` (declared in the component's
   * `convex.config.ts`; set the value via `npx convex env set`). Override only
   * if the app mounts the component under a different secret var.
   */
  signingSecretEnvVar?: string;
  /** Optional caller-authentication seam. See {@link VerifyCaller}. STUBBED. */
  verifyCaller?: VerifyCaller;
  /** Optional billing seam. See {@link BillingCheck}. STUBBED. */
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
 * `verifyCaller`/`billingCheck` slots remain stubbed (P7/P5), and the optional
 * app-mounted HTTP handlers (the Twilio pattern: defined in client code so they
 * can read the app's `ctx.auth`/env and call {@link VerifyCaller}) land later.
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

  constructor(
    public readonly component: ComponentApi,
    public readonly options: AgentToolsOptions = {}
  ) {
    this.gate = {
      checkTool: (ctx, subject, opts) =>
        ctx.runMutation(component.enforce.checkTool, {subject, ...opts})
    };
    this.policy = {
      grant: (ctx, subject, opts) =>
        ctx.runMutation(component.policy.grant, {subject, ...opts}),
      revokeGrant: (ctx, subject, opts) =>
        ctx.runMutation(component.policy.revokeGrant, {subject, ...opts}),
      setToolRisk: (ctx, tool, level) =>
        ctx.runMutation(component.policy.setToolRisk, {tool, level})
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
  }

  /** The env var the component reads its HMAC signing secret from. */
  get signingSecretEnvVar(): string {
    return this.options.signingSecretEnvVar ?? 'TOOLS_SIGNING_SECRET';
  }
}
