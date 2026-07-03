import {defineSchema, defineTable} from 'convex/server';
import {v} from 'convex/values';
import {
  argumentConstraintValidator,
  decisionValidator,
  nullableString,
  reasonCodeValidator,
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
   * Append-only record of EVERY attempted call — allowed or denied. `argDigest`
   * is the redacted digest (never raw args); `reason` is the machine-readable
   * code; `approvalId` is always null in P1 (approvals are P3). This is the
   * operational call log; `audit` is the decision-of-record. Both are written in
   * the same mutation so they never diverge.
   */
  toolCalls: defineTable({
    subject: v.string(),
    agent: nullableString,
    tool: v.string(),
    argDigest: v.string(),
    decision: decisionValidator,
    reason: nullableReason,
    correlationId: v.string(),
    approvalId: v.null(),
    ts: v.number()
  })
    .index('by_subject_ts', ['subject', 'ts'])
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
    .index('by_correlation', ['correlationId'])
});
