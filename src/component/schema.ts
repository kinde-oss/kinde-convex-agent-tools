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
   * `riskLevel` feeds the P3 approval gate.
   *
   * P7 — `agent` and the `by_agent` index are SEEDED BUT UNQUERIED. Every grant
   * written today has `agent: null`, and the spine looks grants up by
   * `by_subject` only (`enforce.ts` hardcodes `agent = null`), so NOTHING reads
   * `by_agent` yet. They exist so agent-scoped grants compose cleanly when the
   * caller-identity work lands; writing an agent-scoped grant now would simply
   * never match. See the README's "P7 roadmap" section.
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
   *
   * The row carries TWO digests of the same args, with different jobs:
   *   - `argDigest`  — the REDACTED display digest (`redactArgs`), shown to the
   *     human approver and matching the decision row. Non-cryptographic.
   *   - `argBinding` — the SHA-256 ARGUMENT BINDING (`argBindingDigest`), which
   *     is what `checkTool` actually compares when consuming this ticket. It is
   *     never displayed. Keeping them separate means the value a human reads can
   *     stay redacted while the value that GATES the call stays collision-resistant.
   */
  approvals: defineTable({
    toolCallRef: v.id('toolCalls'),
    subject: v.string(),
    agent: nullableString,
    tool: v.string(),
    argDigest: v.string(),
    argBinding: v.string(),
    correlationId: v.string(),
    status: approvalStatusValidator,
    requestedBy: nullableString,
    policy: riskLevelValidator,
    resolvedBy: nullableString,
    resolvedAt: nullableNumber,
    resolvedReason: nullableString,
    // A single-use ticket: `null` until the risk step consumes it on the next
    // matching checkTool, then the timestamp it was consumed. An approved
    // approval authorizes exactly ONE call for its `argDigest`.
    consumedAt: nullableNumber,
    expiresAt: nullableNumber,
    createdAt: v.number()
  })
    .index('by_status', ['status'])
    .index('by_call', ['toolCallRef'])
    .index('by_correlation', ['correlationId'])
    // Lets the risk step find an approved, unconsumed ticket for this
    // subject+tool efficiently; the small result set is matched by argDigest
    // in memory.
    .index('by_subject_tool_status', ['subject', 'tool', 'status']),

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
    // Indexes back the read-only `audit.query`, each ordered newest-first via
    // `.order('desc')`. Every supported filter (and the one supported
    // combination) maps to an EXACT index so paginator returns full pages and
    // the cursor is honored without dropping matches:
    //   by_subject_ts          → subject only
    //   by_decision_ts         → decision only
    //   by_subject_decision_ts → subject AND decision (compound, exact)
    //   by_correlation         → correlationId (bounded per call)
    //   by_ts                  → unfiltered newest-first scan
    .index('by_subject_ts', ['subject', 'ts'])
    .index('by_correlation', ['correlationId'])
    .index('by_decision_ts', ['decision', 'ts'])
    .index('by_subject_decision_ts', ['subject', 'decision', 'ts'])
    .index('by_ts', ['ts']),

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
