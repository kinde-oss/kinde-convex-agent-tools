import {v} from 'convex/values';
import type {Infer} from 'convex/values';
import {mutation} from './_generated/server.js';
import {fail} from './errors.js';
import {evaluateConstraints} from './helpers.js';
import {redactArgs} from './redact.js';
import {
  argsValidator,
  decisionValidator,
  denyCodeValidator,
  nullableString
} from './validators.js';
import type {Decision, DenyCode, ReasonCode} from './validators.js';

/**
 * The machine-readable decision returned to the caller. `reason` is present
 * ONLY on a deny (it is a {@link denyCodeValidator} code); an allow omits it.
 * `correlationId` always round-trips: the caller's id if supplied, otherwise a
 * freshly generated one.
 */
const decisionResultValidator = v.object({
  decision: decisionValidator,
  reason: v.optional(denyCodeValidator),
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
 * Precedence (first conclusive step wins; all exits funnel through `allow`/`deny`
 * so exactly one decision is recorded):
 *   a. Identity — the subject is trusted input in P1 (the `verifyCaller` slot is
 *      P7); `agent` is null until agent-scoped identity lands.
 *   b. Allowlist (DENY-BY-DEFAULT) — a matching `toolGrant` for (subject, tool)
 *      must exist. No grant → deny `no_grant`. This is the headline inversion.
 *   c. Argument policy — constraints from the grant and the tool policy are
 *      evaluated against `args`; a violation → deny `argument_denied`. A
 *      contradictory config (a `noArgs` tool carrying constraints) is a typed
 *      failure, never coerced.
 *   d. Budget — NO-OP in P1 (billing seam is P5). // SEAM
 *   e. Risk — NO-OP in P1 (approvals are P3). // SEAM
 *
 * Internal for now: the public client method wrapping this is P2.
 */
export const checkTool = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    args: v.optional(argsValidator),
    correlationId: v.optional(nullableString)
  },
  returns: decisionResultValidator,
  handler: async (ctx, args) => {
    const now = Date.now();
    const callArgs = args.args ?? {};
    const incomingCorrelationId = args.correlationId ?? null;
    // Agent-scoped identity is P7; in P1 the subject is the acting identity and
    // every record is subject-scoped.
    const agent = null;
    const argDigest = redactArgs(callArgs);

    // The single write funnel: one audit row (decision-of-record) + one paired
    // toolCalls row, both stamped with the same correlation id and reason. Every
    // conclusive branch below returns through `allow`/`deny`, so a decision
    // writes exactly one audit row and never more.
    const writeDecision = async (
      decision: Decision,
      reason: ReasonCode
    ): Promise<string> => {
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
      await ctx.db.insert('toolCalls', {
        subject: args.subject,
        agent,
        tool: args.tool,
        argDigest,
        decision,
        reason,
        correlationId,
        approvalId: null,
        ts: now
      });
      return correlationId;
    };

    const allow = async (): Promise<DecisionResult> => {
      const correlationId = await writeDecision('allow', 'granted');
      return {decision: 'allow', correlationId};
    };

    const deny = async (reason: DenyCode): Promise<DecisionResult> => {
      const correlationId = await writeDecision('deny', reason);
      return {decision: 'deny', reason, correlationId};
    };

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

    // d. Budget — NO-OP in P1 (billing seam is P5). // SEAM
    // e. Risk — NO-OP in P1 (approvals are P3). // SEAM

    return await allow();
  }
});
