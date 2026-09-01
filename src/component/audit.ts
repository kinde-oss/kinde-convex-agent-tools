import {v} from 'convex/values';
import {
  paginationOptsValidator,
  paginationResultValidator
} from 'convex/server';
import {paginator} from 'convex-helpers/server/pagination';
import {
  mutation as defineMutation,
  query as defineQuery
} from './_generated/server.js';
import schema from './schema.js';
import {fail} from './errors.js';
import {redactArgs} from './redact.js';
import {argsValidator, decisionValidator} from './validators.js';

const auditDoc = schema.tables.audit.validator.extend({
  _id: v.id('audit'),
  _creationTime: v.number()
});

/**
 * Read-only, paginated, filterable view over the audit trail. NEVER writes. It
 * returns the stored rows, which carry only the REDACTED `argDigest` — raw
 * arguments never reach this table, so they can never be read here.
 *
 * In-component pagination uses convex-helpers `paginator` (the built-in
 * `.paginate()` does not work inside a component), `.order('desc')` for
 * newest-first. Correctness by construction: every supported filter — and the
 * one supported COMBINATION (subject + decision) — maps to an EXACT index, so
 * paginator returns full pages and the cursor is honored WITHOUT any
 * load-bearing post-filter that could drop matches and under-fill a page:
 *   - subject + decision → `by_subject_decision_ts` (eq subject, eq decision)
 *   - subject only       → `by_subject_ts`          (eq subject)
 *   - decision only      → `by_decision_ts`         (eq decision)
 *   - none               → `by_ts`
 * These paths do NO in-memory filtering — the page is exactly what paginator
 * produced.
 *
 * SINGLE BOUNDED EXCEPTION: when `correlationId` is supplied it is the most
 * selective filter, so `by_correlation` (eq correlationId) is used. A
 * correlation groups only a handful of rows for ONE call, so if `subject` or
 * `decision` is ALSO supplied the remaining predicate is applied in memory. This
 * is bounded by one correlation id (not by page size), so — unlike a secondary
 * filter over an open-ended subject/decision scan — it cannot leave matching
 * rows stranded behind full pages of non-matches.
 */
export const query = defineQuery({
  args: {
    paginationOpts: paginationOptsValidator,
    subject: v.optional(v.string()),
    correlationId: v.optional(v.string()),
    decision: v.optional(decisionValidator)
  },
  returns: paginationResultValidator(auditDoc),
  handler: async (ctx, args) => {
    const {subject, correlationId, decision} = args;
    const pager = paginator(ctx.db, schema).query('audit');

    // Bounded exception: correlationId is the most selective filter. Any further
    // subject/decision predicate is narrowed in memory over the (small, bounded)
    // set of rows for this one correlation.
    if (correlationId !== undefined) {
      const result = await pager
        .withIndex('by_correlation', (q) =>
          q.eq('correlationId', correlationId)
        )
        .order('desc')
        .paginate(args.paginationOpts);
      if (subject === undefined && decision === undefined) {
        return result;
      }
      const page = result.page.filter(
        (row) =>
          (subject === undefined || row.subject === subject) &&
          (decision === undefined || row.decision === decision)
      );
      return {...result, page};
    }

    // Every other supported filter/combination is index-EXACT — no post-filter.
    const ordered =
      subject !== undefined && decision !== undefined
        ? pager.withIndex('by_subject_decision_ts', (q) =>
            q.eq('subject', subject).eq('decision', decision)
          )
        : subject !== undefined
          ? pager.withIndex('by_subject_ts', (q) => q.eq('subject', subject))
          : decision !== undefined
            ? pager.withIndex('by_decision_ts', (q) =>
                q.eq('decision', decision)
              )
            : pager.withIndex('by_ts', (q) => q);

    return await ordered.order('desc').paginate(args.paginationOpts);
  }
});

/**
 * Append the ONE completion audit row for an allowed tool that actually
 * executed. Called by the client's `gate.runTool` AFTER `fn()` runs app-side,
 * so it is a distinct, later event from the decision row — not a re-decision.
 * It keeps `decision: 'allow'` (the call was allowed) and stamps the new
 * `reason: 'executed'`, correlated to the decision by `correlationId`.
 *
 * It writes to `audit` ONLY (never a second `toolCalls` row — execution is not a
 * new call attempt). The `argDigest` is recomputed from the same args via the
 * same pure `redactArgs`, so it matches the decision row's digest exactly and
 * still never stores raw args.
 *
 * A COMPLETION ROW MUST CORRELATE TO A REAL ALLOW DECISION, so the audit stream
 * cannot contain executions that were never authorized. This mutation — like
 * every other in the component — cannot see who is calling it, so it does not
 * merely trust its caller to have run the spine first: it VERIFIES that this
 * component itself wrote an `allow` decision for the same
 * (correlationId, subject, tool, argDigest), and fails closed with
 * `no_matching_decision` if not. Without that check, a completion is
 * unfalsifiable history: any caller could append "tool X ran for subject Y" for
 * a call that was denied, or that never happened at all, and the trail would be
 * indistinguishable from a real execution. Validating here makes a forged
 * completion structurally impossible rather than merely discouraged.
 *
 * `argDigest` is part of that key because a completion names the args it ran
 * with. Matching on (correlationId, subject, tool) alone would let a completion
 * claim args the decision never evaluated — the spine allows `{amount: 5}` and
 * the trail records `{amount: 5000}` as executed under it. Both digests come
 * from the same `redactArgs`, so the decision and its completion agree exactly
 * or the completion is refused.
 *
 * SCOPE — this argDigest match is an AUDIT-CONSISTENCY check, not an
 * authorization gate, and `redactArgs` is deliberately the right tool for it.
 * The digest is FNV-1a, so a caller who ALREADY HOLDS a genuine allow decision
 * could in principle craft colliding args and mislabel their own authorized
 * call. That is the ceiling of the attack: it cannot manufacture authorization,
 * only misdescribe a call the spine really allowed. The two checks that gate
 * authority are collision-resistant — the allow decision must exist (above),
 * and an approval's single-use ticket is bound by the SHA-256 `argBinding` in
 * `digest.ts`. Comparing against the stored `argDigest` is what keeps this
 * mutation honest about the row it is validating against.
 *
 * The prior-decision lookup EXCLUDES `executed` rows (which are themselves
 * `decision: 'allow'`), so the audit stream can never self-certify: a completion
 * must point back to a genuine decision, never to another completion.
 *
 * Duplicate completions are an IDEMPOTENT NO-OP, not an error. `runTool` calls
 * this AFTER the tool's side effects have already happened, so throwing here
 * would turn a successful run into a caller-visible failure it cannot undo —
 * and a replayed completion should add nothing to the trail rather than inflate
 * it. Returning quietly is the outcome both callers already expect (neither
 * reads a return value).
 */
export const recordCompletion = defineMutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    args: v.optional(argsValidator),
    correlationId: v.string()
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    // The completion's OWN digest, from the same pure `redactArgs` the spine
    // used for the decision row — so identical args always produce an identical
    // digest and the comparison below is exact.
    const argDigest = redactArgs(args.args ?? {});

    // Bounded by ONE correlation id (a handful of rows for a single call), so
    // the in-memory narrowing here is safe — the same bounded-exception
    // argument the `query` above makes for `by_correlation`.
    const correlated = await ctx.db
      .query('audit')
      .withIndex('by_correlation', (q) =>
        q.eq('correlationId', args.correlationId)
      )
      .collect();
    // The full identity of a call is (correlationId, subject, tool, args) —
    // `argDigest` included. Without it, a completion could name args the
    // decision never saw and the trail would read as though THOSE args were
    // authorized.
    const forThisCall = correlated.filter(
      (row) =>
        row.subject === args.subject &&
        row.tool === args.tool &&
        row.argDigest === argDigest
    );

    // Already completed → no-op. Idempotent on the same key the decision is
    // validated against, so a different tool (or different args) sharing a
    // correlation id can still record its own completion.
    if (forThisCall.some((row) => row.reason === 'executed')) {
      return null;
    }

    // The decision of record must exist, must be THIS component's, must be an
    // allow, and must be for THESE args. A deny/approve row, a row for
    // different args, or no row at all fails closed.
    const authorized = forThisCall.some(
      (row) => row.decision === 'allow' && row.reason !== 'executed'
    );
    if (!authorized) {
      fail(
        'no_matching_decision',
        'No allow decision exists for this correlationId, subject, tool and args; a completion cannot be recorded.'
      );
    }

    await ctx.db.insert('audit', {
      subject: args.subject,
      agent: null,
      tool: args.tool,
      argDigest,
      decision: 'allow',
      reason: 'executed',
      correlationId: args.correlationId,
      ts: Date.now()
    });
    return null;
  }
});
