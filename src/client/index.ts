import type {GenericActionCtx, GenericDataModel} from 'convex/server';
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
 * P0 is a shell: it holds the component reference and the composition options.
 * The decision API (`allow` / `deny` / `require-human-approval`), the
 * deny-by-default allowlist, metering, and the single audit row per call arrive
 * in later phases as thin pass-throughs to component functions. The optional
 * app-mounted HTTP handlers (the Twilio pattern: defined in client code so they
 * can read the app's `ctx.auth`/env and call {@link VerifyCaller}) also land
 * later; the seam is the client-owns-the-handler shape, not core code.
 */
export class AgentTools {
  constructor(
    public readonly component: ComponentApi,
    public readonly options: AgentToolsOptions = {}
  ) {}

  /** The env var the component reads its HMAC signing secret from. */
  get signingSecretEnvVar(): string {
    return this.options.signingSecretEnvVar ?? 'TOOLS_SIGNING_SECRET';
  }
}
