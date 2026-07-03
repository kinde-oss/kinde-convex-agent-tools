import {defineSchema, defineTable} from 'convex/server';
import {v} from 'convex/values';
import {
  approvalStatusValidator,
  argumentConstraintValidator,
  decisionValidator,
  nullableNumber,
  nullableString,
  reasonCodeValidator,
  revocationLevelValidator,
  riskLevelValidator
} from './validators.js';

const nullableReason = v.union(reasonCodeValidator, v.null());
const nullableConstraints = v.union(
  v.array(argumentConstraintValidator),
  v.null()
);

export default defineSchema({
  /**
   * The allowlist: which tools a subject (or, later, a specific agent) may call.
   * Deny-by-default lives here — the ABSENCE of a matching row is the denial. An
   * optional `argumentConstraints` narrows WHICH calls are allowed; an optional
   * `riskLevel` feeds the P3 approval gate. `agent` is nullable: a subject-scoped
   * grant has `agent: null`; agent-scoped grants arrive with the caller-identity
   * work in P7 (the `by_agent` index is seeded now so that composes cleanly).
   */
  toolGrants: defineTable({
    subject: v.string(),
    agent: nullableString,
    tool: v.string(),
    argumentConstraints: nullableConstraints,
    riskLevel: v.union(riskLevelValidator, v.null()),
    createdAt: v.number()
  })
    .index('by_subject', ['subject', 'tool'])
    .index('by_agent', ['agent', 'tool'])
    .index('by_tool', ['tool']),

  /**
   * Per-tool policy: a global risk level and global argument-constraint rules
   * that apply to the tool regardless of grant, plus `noArgs` marking a tool
   * that takes no arguments. A tool marked `noArgs` MUST NOT carry argument
   * constraints (checked at decision time) — that pairing is contradictory.
   */
  toolPolicies: defineTable({
    tool: v.string(),
    riskLevel: v.union(riskLevelValidator, v.null()),
    noArgs: v.boolean(),
    argumentConstraints: nullableConstraints
  }).index('by_tool', ['tool']),

  /**
   * Append-only record of EVERY attempted call — allowed, denied, or sent to
   * approval. `argDigest` is the redacted digest (never raw args); `reason` is
   * the machine-readable code. `approvalId` is null for allow/deny; on an
   * `approve` decision it back-references the `approvals` row created in the
   * same mutation (the canonical link is `approvals.toolCallRef`; this is the
   * convenience reverse pointer). This is the operational call log; `audit` is
   * the decision-of-record. Both are written in the same mutation so they never
   * diverge.
   */
  toolCalls: defineTable({
    subject: v.string(),
    agent: nullableString,
    tool: v.string(),
    argDigest: v.string(),
    decision: decisionValidator,
    reason: nullableReason,
    correlationId: v.string(),
    approvalId: v.union(v.id('approvals'), v.null()),
    ts: v.number()
  })
    .index('by_subject_ts', ['subject', 'ts'])
    .index('by_correlation', ['correlationId']),

  /**
   * A human-in-the-loop approval request, created when the risk gate routes a
   * call to `approve`. Exactly one per approve decision, linked to its call via
   * `toolCallRef` (canonical) and carrying the same redacted `argDigest`,
   * `correlationId`, and triggering risk (`policy`) so the request is auditable
   * without re-reading the call. `status` moves pending → approved | denied; a
   * pending row past `expiresAt` is treated as `expired` on read (lazy, never
   * persisted). `resolvedBy`/`resolvedAt` record the human resolver.
   */
  approvals: defineTable({
    toolCallRef: v.id('toolCalls'),
    subject: v.string(),
    agent: nullableString,
    tool: v.string(),
    argDigest: v.string(),
    correlationId: v.string(),
    status: approvalStatusValidator,
    requestedBy: nullableString,
    policy: riskLevelValidator,
    resolvedBy: nullableString,
    resolvedAt: nullableNumber,
    resolvedReason: nullableString,
    expiresAt: nullableNumber,
    createdAt: v.number()
  })
    .index('by_status', ['status'])
    .index('by_call', ['toolCallRef'])
    .index('by_correlation', ['correlationId']),

  /**
   * The audit trail: EXACTLY ONE row per decision (decision atomicity), carrying
   * a correlation id, a machine-readable reason code, the tool, and the REDACTED
   * argument digest. Never updated or deleted; never stores raw argument values.
   */
  audit: defineTable({
    subject: v.string(),
    agent: nullableString,
    tool: v.string(),
    argDigest: v.string(),
    decision: decisionValidator,
    reason: nullableReason,
    correlationId: v.string(),
    ts: v.number()
  })
    .index('by_subject_ts', ['subject', 'ts'])
    .index('by_correlation', ['correlationId']),

  /**
   * The revocation overlay: a reactive kill switch checked by the spine BEFORE
   * the allowlist, so a revoked target denies even with a valid grant. A
   * revocation is NON-DESTRUCTIVE — it never touches the grant. `targetType` +
   * `targetId` name what is revoked, keyed as:
   *   - `global` → `targetId` is null (revokes everything);
   *   - `org`    → the org code;
   *   - `agent`  → the agent id;
   *   - `grant`  → the (subject, tool) key `JSON.stringify([subject, tool])`
   *                (see `grantRevocationKey`).
   * Lifting is NON-destructive too: `active` flips to false and the overlay
   * ignores inactive rows (history is preserved). At most one row exists per
   * (targetType, targetId) — it is reused across revoke/lift cycles.
   */
  revocations: defineTable({
    targetType: revocationLevelValidator,
    targetId: nullableString,
    reason: v.string(),
    revokedBy: nullableString,
    active: v.boolean(),
    createdAt: v.number()
  })
    .index('by_target', ['targetType', 'targetId'])
    .index('by_active', ['active'])
});
