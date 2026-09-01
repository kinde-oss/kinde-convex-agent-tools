import {v} from 'convex/values';
import type {Infer} from 'convex/values';
import type {FunctionHandle} from 'convex/server';
import {mutation} from './_generated/server.js';
import type {Id} from './_generated/dataModel.js';
import {fail} from './errors.js';
import {
  effectiveRisk,
  evaluateConstraints,
  parseBillingResult,
  requiresApproval,
  resolveRevocation
} from './helpers.js';
import {activeRevocationLevels} from './revocations.js';
import {argBindingDigest} from './digest.js';
import {redactArgs} from './redact.js';
import {
  argsValidator,
  decisionValidator,
  denyCodeValidator,
  nullableString
} from './validators.js';
import type {
  BillingCheckPayload,
  Decision,
  DenyCode,
  ReasonCode,
  RiskLevel
} from './validators.js';

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
 *   d. Budget — the OPTIONAL injected billing seam (P5). When the client threads
 *      a `billingCheck` FunctionHandle, the spine invokes it IN THIS TRANSACTION
 *      with a redacted payload (never raw args); a not-allowed result denies
 *      `budget_exceeded`. Absent → skipped (standalone operation unchanged). The
 *      component imports no billing package — the check is injected, not
 *      imported. Runs AFTER argument policy (a failed policy never consults
 *      billing) and BEFORE risk.
 *   e. Risk — the effective risk (the stricter of grant vs tool-policy risk) is
 *      resolved; if it requires approval (threshold: `high`), a single-use
 *      approved ticket for this exact subject+tool+argBinding is consumed and the
 *      call ALLOWED (`approval_consumed`); otherwise the call routes to `approve`
 *      (one pending approvals row created) instead of allow. `argBinding` is the
 *      SHA-256 argument binding (see `digest.ts`) — distinct from the redacted
 *      `argDigest` that is recorded for display, because a ticket match is a
 *      security decision and must be collision-resistant.
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
    approvalTtlMs: v.optional(v.number()),
    // Optional billing seam: a serialized FunctionHandle (see convex
    // `createFunctionHandle`) to an app-provided mutation the client threads in.
    // The spine invokes it during the budget step; absent → budget skipped.
    billingCheck: v.optional(v.string())
  },
  returns: decisionResultValidator,
  handler: async (ctx, args) => {
    const now = Date.now();
    const callArgs = args.args ?? {};
    // One correlation id for the whole call — used by the billing payload and by
    // the single decision row, so they always share it.
    const correlationId = args.correlationId ?? crypto.randomUUID();
    // P7 — NOT WIRED YET. `agent` is hardcoded null: the subject is the acting
    // identity and every record is subject-scoped. The HTTP seam's
    // `VerifiedCaller` already ACCEPTS `org`/`agent` (see `client/http.ts`) and
    // `toolGrants` already carries an `agent` field with a `by_agent` index, but
    // NOTHING threads either into this decision spine today. The consequences to
    // be explicit about:
    //   - an agent-scoped grant is never matched (the allowlist looks up by
    //     subject only), and
    //   - an ORG- or AGENT-level revocation from agent-auth CANNOT deny a call
    //     here — `activeRevocationLevels` is passed null for both below, so only
    //     the global and grant levels can ever fire.
    // Accepted for forward compatibility so the shapes compose cleanly when P7
    // lands; see the README's "P7 roadmap" section.
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

    const allow = async (
      reason: ReasonCode = 'granted'
    ): Promise<DecisionResult> => {
      const {correlationId} = await record('allow', reason, null);
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
    const approve = async (
      riskPolicy: RiskLevel,
      argBinding: string
    ): Promise<DecisionResult> => {
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
        argBinding,
        correlationId,
        status: 'pending',
        requestedBy: args.subject,
        policy: riskPolicy,
        resolvedBy: null,
        resolvedAt: null,
        resolvedReason: null,
        consumedAt: null,
        expiresAt:
          args.approvalTtlMs === undefined ? null : now + args.approvalTtlMs,
        createdAt: now
      });
      await ctx.db.patch('toolCalls', toolCallId, {approvalId});
      return {decision: 'approve', approvalId, correlationId};
    };

    // a.5 Revocation overlay: an ACTIVE kill switch that short-circuits BEFORE
    // the allowlist. Re-queried every call (no caching) so a revoke denies the
    // very next checkTool.
    //
    // P7 — `org` and `agent` are passed null (see the `agent` declaration
    // above). The query STRUCTURALLY supports both levels, but with null inputs
    // the org and agent branches can never match, so only `global` and `grant`
    // revocations are enforceable today. Revoking an org or an agent in
    // agent-auth does NOT deny tool calls here until P7 threads a verified
    // org/agent in; see the README's "P7 roadmap" section.
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

    // d. Budget — the optional injected billing seam. When a `billingCheck`
    // handle is threaded in, invoke it IN THIS TRANSACTION with a REDACTED
    // payload (never raw args) and deny `budget_exceeded` on a not-allowed
    // result. The return is validated (a malformed shape is a typed fail, never
    // a silent allow). Absent → skipped, so standalone operation is unchanged.
    if (args.billingCheck !== undefined) {
      const handle = args.billingCheck as FunctionHandle<
        'mutation',
        BillingCheckPayload,
        unknown
      >;
      const result = parseBillingResult(
        await ctx.runMutation(handle, {
          subject: args.subject,
          tool: args.tool,
          argDigest,
          correlationId
        })
      );
      if (!result.allow) {
        return await deny('budget_exceeded');
      }
    }

    // e. Risk — resolve the effective (stricter) risk and route high-risk calls
    // to human approval. A single-use ticket: before minting a NEW pending
    // approval, look for one already `approved`, UNEXPIRED and unconsumed for
    // this exact subject+tool+argBinding. If found, consume it (mark
    // `consumedAt`) and ALLOW this one call; a later call must be approved
    // afresh. The argBinding match is the argument binding — an approval for
    // argsA never authorizes argsB.
    const risk = effectiveRisk(grant.riskLevel, policy?.riskLevel ?? null);
    if (risk !== null && requiresApproval(risk)) {
      // The SHA-256 binding is computed ONLY here, on the approval path — the
      // one place it is load-bearing — so the common allow/deny paths do no
      // crypto work. Minting (below) and matching (here) both go through the
      // same `argBindingDigest`, so they cannot drift.
      const argBinding = await argBindingDigest(callArgs);
      const candidates = await ctx.db
        .query('approvals')
        .withIndex('by_subject_tool_status', (q) =>
          q
            .eq('subject', args.subject)
            .eq('tool', args.tool)
            .eq('status', 'approved')
        )
        .collect();
      // The oldest approved, unconsumed, UNEXPIRED ticket for this exact
      // binding (bounded, few rows). An approved ticket past its `expiresAt` is
      // dead — resolution-time expiry only guards PENDING approvals, so it must
      // also be enforced here or a stale approval could authorize a call long
      // after its TTL. Oldest-first is deterministic if several ever match.
      //
      // The match is on `argBinding` (SHA-256), NOT the redacted `argDigest`:
      // this comparison is what makes an approval argument-bound, so it must be
      // infeasible to craft args that collide with an approved ticket's digest.
      const ticket = candidates
        .filter(
          (a) =>
            a.consumedAt === null &&
            a.argBinding === argBinding &&
            (a.expiresAt === null || a.expiresAt >= now)
        )
        .sort(
          (a, b) =>
            a.createdAt - b.createdAt || a._creationTime - b._creationTime
        )[0];
      if (ticket !== undefined) {
        await ctx.db.patch('approvals', ticket._id, {consumedAt: now});
        return await allow('approval_consumed');
      }
      return await approve(risk, argBinding);
    }

    // f. Otherwise → allow.
    return await allow();
  }
});
