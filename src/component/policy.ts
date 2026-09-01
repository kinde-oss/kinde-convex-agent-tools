import {v} from 'convex/values';
import {mutation} from './_generated/server.js';
import type {Id} from './_generated/dataModel.js';
import {fail} from './errors.js';
import {assertConstraintsWellFormed} from './helpers.js';
import {argumentConstraintValidator, riskLevelValidator} from './validators.js';

const nullableConstraints = v.union(
  v.array(argumentConstraintValidator),
  v.null()
);

/**
 * Upsert a subject-scoped grant for (subject, tool) — the allowlist entry the
 * spine looks up. Idempotent on (subject, tool): a second grant for the same
 * pair UPDATES the existing row rather than creating a duplicate, so the
 * allowlist stays single-valued. The constraint set is validated HERE at grant
 * time (fail fast) as well as at decision time, so a contradictory set (empty
 * `allowValues`, `min > max`, …) is rejected before it is ever stored.
 *
 * MERGE semantics on update (no silent privilege changes): an OMITTED
 * `argumentConstraints`/`risk` preserves the existing value — updating only the
 * risk can never silently wipe the constraints, and vice versa. Clearing is
 * always EXPLICIT: pass `null` for the field you mean to clear.
 *
 * `agent` is null in P2 (agent-scoped grants arrive with caller identity in P7).
 */
export const grant = mutation({
  args: {
    subject: v.string(),
    tool: v.string(),
    argumentConstraints: v.optional(nullableConstraints),
    risk: v.optional(v.union(riskLevelValidator, v.null()))
  },
  returns: v.id('toolGrants'),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('toolGrants')
      .withIndex('by_subject', (q) =>
        q.eq('subject', args.subject).eq('tool', args.tool)
      )
      .unique();

    // undefined = "leave as-is" (falls back to the existing value); null =
    // "explicitly clear". This is what stops a risk-only update from wiping
    // constraints (or a constraints-only update from wiping the risk gate).
    const argumentConstraints =
      args.argumentConstraints !== undefined
        ? args.argumentConstraints
        : (existing?.argumentConstraints ?? null);
    const riskLevel =
      args.risk !== undefined ? args.risk : (existing?.riskLevel ?? null);
    if (argumentConstraints !== null) {
      assertConstraintsWellFormed(argumentConstraints);
    }

    let grantId: Id<'toolGrants'>;
    if (existing !== null) {
      await ctx.db.patch('toolGrants', existing._id, {
        argumentConstraints,
        riskLevel
      });
      grantId = existing._id;
    } else {
      grantId = await ctx.db.insert('toolGrants', {
        subject: args.subject,
        agent: null,
        tool: args.tool,
        argumentConstraints,
        riskLevel,
        createdAt: Date.now()
      });
    }
    return grantId;
  }
});

/**
 * Delete the (subject, tool) grant. Deny-by-default makes the deletion itself
 * the revocation — the next `checkTool` re-queries `toolGrants`, finds nothing,
 * and denies `no_grant` (reactive revocation). Revoking a grant that does not
 * exist is a typed `grant_not_found` failure, NOT a silent no-op, so a caller
 * can never believe it revoked something it didn't.
 */
export const revokeGrant = mutation({
  args: {
    subject: v.string(),
    tool: v.string()
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('toolGrants')
      .withIndex('by_subject', (q) =>
        q.eq('subject', args.subject).eq('tool', args.tool)
      )
      .unique();
    if (existing === null) {
      fail(
        'grant_not_found',
        `No grant to revoke for subject '${args.subject}' and tool '${args.tool}'.`
      );
    }
    await ctx.db.delete('toolGrants', existing._id);
    return null;
  }
});

/**
 * Upsert the per-tool policy's risk level, creating the policy row if absent
 * (with `noArgs: false` and no global constraints). Risk feeds the P3 approval
 * gate; setting it does not by itself change any decision in P2.
 */
export const setToolRisk = mutation({
  args: {
    tool: v.string(),
    level: riskLevelValidator
  },
  returns: v.id('toolPolicies'),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('toolPolicies')
      .withIndex('by_tool', (q) => q.eq('tool', args.tool))
      .unique();

    if (existing !== null) {
      await ctx.db.patch('toolPolicies', existing._id, {
        riskLevel: args.level
      });
      return existing._id;
    }
    return await ctx.db.insert('toolPolicies', {
      tool: args.tool,
      riskLevel: args.level,
      noArgs: false,
      argumentConstraints: null
    });
  }
});

/**
 * Upsert the per-tool ARGUMENT policy: `noArgs` (the tool takes no arguments)
 * and/or global `argumentConstraints` that apply to the tool regardless of
 * grant. The evaluator already consumes both — this is their admin writer,
 * completing the `toolPolicies` surface alongside `setToolRisk`.
 *
 * MERGE semantics, like `grant`: an OMITTED field preserves the existing value
 * (and `riskLevel` is never touched here); clearing constraints is explicit via
 * `null`. Constraints are validated exactly as at grant time (empty
 * `allowValues`, `min > max`, … → typed `invalid_constraint`), and the
 * contradictory pairing the spine rejects at decision time — `noArgs` with a
 * non-empty constraint set — is rejected HERE at write time too, against the
 * MERGED result, so the contradiction can never be stored.
 */
export const setToolPolicy = mutation({
  args: {
    tool: v.string(),
    noArgs: v.optional(v.boolean()),
    argumentConstraints: v.optional(nullableConstraints)
  },
  returns: v.id('toolPolicies'),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('toolPolicies')
      .withIndex('by_tool', (q) => q.eq('tool', args.tool))
      .unique();

    const noArgs =
      args.noArgs !== undefined ? args.noArgs : (existing?.noArgs ?? false);
    const argumentConstraints =
      args.argumentConstraints !== undefined
        ? args.argumentConstraints
        : (existing?.argumentConstraints ?? null);
    if (argumentConstraints !== null) {
      assertConstraintsWellFormed(argumentConstraints);
    }
    if (
      noArgs &&
      argumentConstraints !== null &&
      argumentConstraints.length > 0
    ) {
      fail(
        'contradictory_constraint',
        `Tool '${args.tool}' cannot be marked no-args and carry argument constraints.`
      );
    }

    if (existing !== null) {
      await ctx.db.patch('toolPolicies', existing._id, {
        noArgs,
        argumentConstraints
      });
      return existing._id;
    }
    return await ctx.db.insert('toolPolicies', {
      tool: args.tool,
      riskLevel: null,
      noArgs,
      argumentConstraints
    });
  }
});
