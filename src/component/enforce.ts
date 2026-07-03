import {v} from 'convex/values';
import type {Infer} from 'convex/values';
import {mutation} from './_generated/server.js';
import type {Id} from './_generated/dataModel.js';
import {fail} from './errors.js';
import {
  effectiveRisk,
  evaluateConstraints,
  requiresApproval,
  resolveRevocation
} from './helpers.js';
import {activeRevocationLevels} from './revocations.js';
import {redactArgs} from './redact.js';
import {
  argsValidator,
  decisionValidator,
  denyCodeValidator,
  nullableString
} from './validators.js';
import type {Decision, DenyCode, ReasonCode, RiskLevel} from './validators.js';

/**
 * The machine-readable decision returned to the caller. `reason` is present
 * ONLY on a deny (it is a {@link denyCodeValidator} code); `approvalId` is
 * present ONLY on an `approve` outcome. An allow carries neither. `correlationId`
 * always round-trips: the caller's id if supplied, otherwise a freshly generated
 * one.
 */
const decisionResultValidator = v.object({
  decision: decisionValidator,
  reason: v.optional(denyCodeValidator),
  approvalId: v.optional(v.id('approvals')),
  correlationId: v.string()
});
type DecisionResult = Infer<typeof decisionResultValidator>;

/**
 * The decision spine — the correctness root of the component. Given plain
 * inputs (`subject`, `tool`, `args`), it resolves a tool call in ONE Convex
 * mutation and writes EXACTLY ONE audit row (plus its paired toolCalls row),
 * carrying a correlation id, a machine-readable reason code, the tool, and the
 * REDACTED argument digest. Framework-agnostic: no framework or sibling import.
 *
 * Precedence (first conclusive step wins; all exits funnel through
 * `allow`/`deny`/`approve` so exactly one decision is recorded):
 *   a. Identity — the subject is trusted input (the `verifyCaller` slot is P7);
 *      `agent` is null until agent-scoped identity lands.
 *   a.5 Revocation overlay (ACTIVE kill switch) — checked BEFORE the allowlist,
 *      so a revoked target denies `revoked` even with a perfectly valid grant,
 *      and a revoked-AND-ungranted call still denies `revoked` (the overlay
 *      short-circuits, so `revoked` wins over `no_grant`). Precedence among
 *      levels is global > org > agent > grant. Re-queried every call (no
 *      caching) — that is what makes revocation reactive.
 *   b. Allowlist (DENY-BY-DEFAULT) — a matching `toolGrant` for (subject, tool)
 *      must exist. No grant → deny `no_grant`. This is the headline inversion,
 *      and it runs BEFORE risk, so an out-of-allowlist high-risk tool is denied
 *      `no_grant`, never routed to approval.
 *   c. Argument policy — constraints from the grant and the tool policy are
 *      evaluated against `args`; a violation → deny `argument_denied`. A
 *      contradictory config (a `noArgs` tool carrying constraints) is a typed
 *      failure, never coerced.
 *   d. Budget — NO-OP in P3 (billing seam is P5). // SEAM
 *   e. Risk — the effective risk (the stricter of grant vs tool-policy risk) is
 *      resolved; if it requires approval (threshold: `high`), the call routes to
 *      `approve` (one approvals row created) instead of allow.
 *   f. Otherwise → allow.
 */
export const checkTool = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    args: v.optional(argsValidator),
    correlationId: v.optional(nullableString),
    // Optional TTL for an approval created by the risk gate. Ignored on
    // allow/deny; a non-positive value is a contradictory input (typed fail).
    approvalTtlMs: v.optional(v.number())
  },
  returns: decisionResultValidator,
  handler: async (ctx, args) => {
    const now = Date.now();
    const callArgs = args.args ?? {};
    const incomingCorrelationId = args.correlationId ?? null;
    // Agent-scoped identity is P7; the subject is the acting identity and every
    // record is subject-scoped.
    const agent = null;
    const argDigest = redactArgs(callArgs);

    // HARDENING: a non-positive TTL is contradictory input — reject before any
    // write, never coerce it into "no expiry".
    if (args.approvalTtlMs !== undefined && args.approvalTtlMs <= 0) {
      fail('invalid_ttl', 'approvalTtlMs must be greater than 0.');
    }

    // The single write funnel: one audit row (decision-of-record) + one paired
    // toolCalls row, both stamped with the same correlation id and reason. Every
    // conclusive branch below returns through `allow`/`deny`/`approve`, so a
    // decision writes exactly one audit row and never more. Returns the ids so
    // the approve branch can link an approvals row to the toolCalls row.
    const record = async (
      decision: Decision,
      reason: ReasonCode,
      approvalId: Id<'approvals'> | null
    ): Promise<{correlationId: string; toolCallId: Id<'toolCalls'>}> => {
      const correlationId = incomingCorrelationId ?? crypto.randomUUID();
      await ctx.db.insert('audit', {
        subject: args.subject,
        agent,
        tool: args.tool,
        argDigest,
        decision,
        reason,
        correlationId,
        ts: now
      });
      const toolCallId = await ctx.db.insert('toolCalls', {
        subject: args.subject,
        agent,
        tool: args.tool,
        argDigest,
        decision,
        reason,
        correlationId,
        approvalId,
        ts: now
      });
      return {correlationId, toolCallId};
    };

    const allow = async (): Promise<DecisionResult> => {
      const {correlationId} = await record('allow', 'granted', null);
      return {decision: 'allow', correlationId};
    };

    const deny = async (reason: DenyCode): Promise<DecisionResult> => {
      const {correlationId} = await record('deny', reason, null);
      return {decision: 'deny', reason, correlationId};
    };

    // The one `approve` decision: write the call rows, then create the single
    // pending approvals row, then back-link its id onto the toolCalls row — all
    // in this mutation. Still exactly one audit row + one toolCalls row + one
    // approvals row.
    const approve = async (policy: RiskLevel): Promise<DecisionResult> => {
      const {correlationId, toolCallId} = await record(
        'approve',
        'approval_required',
        null
      );
      const approvalId = await ctx.db.insert('approvals', {
        toolCallRef: toolCallId,
        subject: args.subject,
        agent,
        tool: args.tool,
        argDigest,
        correlationId,
        status: 'pending',
        requestedBy: args.subject,
        policy,
        resolvedBy: null,
        resolvedAt: null,
        resolvedReason: null,
        expiresAt:
          args.approvalTtlMs === undefined ? null : now + args.approvalTtlMs,
        createdAt: now
      });
      await ctx.db.patch('toolCalls', toolCallId, {approvalId});
      return {decision: 'approve', approvalId, correlationId};
    };

    // a.5 Revocation overlay: an ACTIVE kill switch that short-circuits BEFORE
    // the allowlist. Re-queried every call (no caching) so a revoke denies the
    // very next checkTool. `org` is not in the identity model yet (null);
    // `agent` is null until P7 — both are structurally supported by the query.
    const revoked = resolveRevocation(
      await activeRevocationLevels(ctx, {
        subject: args.subject,
        tool: args.tool,
        agent,
        org: null
      })
    );
    if (revoked.revoked) {
      return await deny('revoked');
    }

    // b. Allowlist (deny-by-default): the absence of a grant IS the denial.
    const grant = await ctx.db
      .query('toolGrants')
      .withIndex('by_subject', (q) =>
        q.eq('subject', args.subject).eq('tool', args.tool)
      )
      .first();
    if (grant === null) {
      return await deny('no_grant');
    }

    // c. Argument policy: combine the grant's and the tool policy's constraints.
    const policy = await ctx.db
      .query('toolPolicies')
      .withIndex('by_tool', (q) => q.eq('tool', args.tool))
      .unique();

    const constraints = [
      ...(grant.argumentConstraints ?? []),
      ...(policy?.argumentConstraints ?? [])
    ];

    // HARDENING: a tool marked no-args that nonetheless carries argument
    // constraints is a contradictory configuration. Reject with a typed failure
    // (no audit row is written — this is an invalid config, not a decision),
    // never coerce it into a silent allow or deny.
    if (policy?.noArgs === true && constraints.length > 0) {
      fail(
        'contradictory_constraint',
        `Tool '${args.tool}' is marked no-args but has argument constraints.`
      );
    }

    if (constraints.length > 0) {
      const outcome = evaluateConstraints(constraints, callArgs);
      if (!outcome.ok) {
        return await deny(outcome.reason);
      }
    }

    // d. Budget — NO-OP in P3 (billing seam is P5). // SEAM

    // e. Risk — resolve the effective (stricter) risk and route high-risk calls
    // to human approval instead of allowing them outright.
    const risk = effectiveRisk(grant.riskLevel, policy?.riskLevel ?? null);
    if (risk !== null && requiresApproval(risk)) {
      return await approve(risk);
    }

    // f. Otherwise → allow.
    return await allow();
  }
});
