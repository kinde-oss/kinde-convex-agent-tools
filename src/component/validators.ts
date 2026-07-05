import {v} from 'convex/values';
import type {Infer} from 'convex/values';

/**
 * A tool-call decision. Three-valued: `allow`, `deny`, or `approve`. `approve`
 * is the require-human-approval outcome from the P3 risk gate — it is NOT a
 * deny (the call is neither allowed nor rejected yet; a human must resolve it).
 */
export const decisionValidator = v.union(
  v.literal('allow'),
  v.literal('deny'),
  v.literal('approve')
);

/** A tool's risk level. Carried on grants/policies; consumed by the risk gate. */
export const riskLevelValidator = v.union(
  v.literal('low'),
  v.literal('medium'),
  v.literal('high')
);

/**
 * The lifecycle status of an approval request. `pending` awaits a human;
 * `approved`/`denied` are the resolved terminals; `expired` is a DERIVED status
 * (a pending approval past its `expiresAt`) — it is computed on read, never
 * persisted (see approvals.getStatus).
 */
export const approvalStatusValidator = v.union(
  v.literal('pending'),
  v.literal('approved'),
  v.literal('denied'),
  v.literal('expired')
);

/**
 * The level a revocation targets, most → least broad: `global` (everything),
 * `org` (a tenant), `agent` (one agent identity), `grant` (one subject+tool
 * grant). Precedence when several apply is exactly this order — see
 * `resolveRevocation`.
 */
export const revocationLevelValidator = v.union(
  v.literal('global'),
  v.literal('org'),
  v.literal('agent'),
  v.literal('grant')
);

/**
 * The machine-readable reason a call was DENIED. `revoked` is the revocation
 * overlay's active kill switch (short-circuits BEFORE the allowlist).
 * `budget_exceeded` is the injected billing seam's not-allowed result (P5).
 * Never free text.
 */
export const denyCodeValidator = v.union(
  v.literal('no_grant'),
  v.literal('argument_denied'),
  v.literal('revoked'),
  v.literal('budget_exceeded')
);

/**
 * The machine-readable reason stamped on EVERY audit/toolCalls row — the deny
 * codes plus the positive `granted`, the `approval_required` reason on an
 * `approve` decision, and the two resolution reasons appended when a human
 * resolves an approval. Every decision carries one (audit completeness), so
 * this is a superset of {@link denyCodeValidator}.
 */
export const reasonCodeValidator = v.union(
  v.literal('granted'),
  v.literal('no_grant'),
  v.literal('argument_denied'),
  v.literal('revoked'),
  v.literal('budget_exceeded'),
  v.literal('approval_required'),
  v.literal('approval_approved'),
  v.literal('approval_denied'),
  // The ALLOW reason when the risk step consumes a single-use approved ticket
  // (subject+tool+argDigest) instead of minting a new pending approval. An allow
  // reason, NOT a DenyCode.
  v.literal('approval_consumed'),
  // The COMPLETION event appended by runTool after an allowed tool actually
  // executes (audit-only; NOT a DenyCode and NOT a fresh decision).
  v.literal('executed')
);

/**
 * The billing seam contract (P5). The component composes with billing by
 * INVOKING an app-provided function through a {@link FunctionHandle} — it never
 * imports a billing package. `billingCheckPayloadValidator` is what the spine
 * sends (only the REDACTED `argDigest`, never raw args); `billingCheckResult`
 * is what it expects back. Both sides share these validators so the boundary is
 * typed; the component still runtime-validates the RETURN (a malformed return is
 * a typed `billing_check_malformed` failure, never coerced).
 */
export const billingCheckPayloadValidator = v.object({
  subject: v.string(),
  tool: v.string(),
  argDigest: v.string(),
  correlationId: v.string()
});

export const billingCheckResultValidator = v.object({
  allow: v.boolean(),
  reason: v.optional(v.string())
});

/** The scalar values a constraint can carry (never arrays or null). */
const constraintScalar = v.union(v.string(), v.number(), v.boolean());

/**
 * A single, declarative, per-argument constraint. Each `kind` is evaluated
 * independently against the call's args (see `evaluateConstraints`), and the
 * set is deny-by-default: any one violation denies. The shape is a
 * discriminated union, so an ill-typed constraint (e.g. a `max` with a
 * non-numeric `value`) cannot even be stored.
 *
 * Absent-argument semantics differ by kind (this is the subtle part):
 * - `required`: the arg MUST be present and non-null; absent/null → deny. This
 *   is what stops a caller dodging a value check by simply omitting the arg.
 * - `min` / `max`: numeric floor / ceiling. An ABSENT (or null) arg does not
 *   apply — there is nothing to bound. A present non-numeric arg is a typed
 *   `invalid_argument` failure (never coerced), not a deny.
 * - `denyValue`: exact-match denylist — a present arg equal to `value` denies.
 * - `allowValues`: allowlist/enum — a PRESENT arg must be one of `values`;
 *   outside the set → deny. Absent passes (pair with `required` to force it).
 *   An empty `values` set is a contradictory config → typed fail.
 */
export const argumentConstraintValidator = v.union(
  v.object({
    arg: v.string(),
    kind: v.literal('required')
  }),
  v.object({
    arg: v.string(),
    kind: v.literal('min'),
    value: v.number()
  }),
  v.object({
    arg: v.string(),
    kind: v.literal('max'),
    value: v.number()
  }),
  v.object({
    arg: v.string(),
    kind: v.literal('denyValue'),
    value: constraintScalar
  }),
  v.object({
    arg: v.string(),
    kind: v.literal('allowValues'),
    values: v.array(constraintScalar)
  })
);

/**
 * A tool call's arguments: a flat, string-keyed record of JSON-ish primitives
 * and string arrays. Flat by design so the whole value stays fully typed (no
 * `any`) and is cheaply, deterministically redactable for the audit digest.
 */
export const argsValidator = v.record(
  v.string(),
  v.union(v.string(), v.number(), v.boolean(), v.null(), v.array(v.string()))
);

export const nullableString = v.union(v.string(), v.null());
export const nullableNumber = v.union(v.number(), v.null());

export type Decision = Infer<typeof decisionValidator>;
export type RiskLevel = Infer<typeof riskLevelValidator>;
export type RevocationLevel = Infer<typeof revocationLevelValidator>;
export type ApprovalStatus = Infer<typeof approvalStatusValidator>;
export type DenyCode = Infer<typeof denyCodeValidator>;
export type ReasonCode = Infer<typeof reasonCodeValidator>;
export type ArgumentConstraint = Infer<typeof argumentConstraintValidator>;
export type ToolArgs = Infer<typeof argsValidator>;
export type ToolArgValue = ToolArgs[string];
export type BillingCheckPayload = Infer<typeof billingCheckPayloadValidator>;
export type BillingCheckResult = Infer<typeof billingCheckResultValidator>;
