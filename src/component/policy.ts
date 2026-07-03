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
    const argumentConstraints = args.argumentConstraints ?? null;
    const riskLevel = args.risk ?? null;
    if (argumentConstraints !== null) {
      assertConstraintsWellFormed(argumentConstraints);
    }

    const existing = await ctx.db
      .query('toolGrants')
      .withIndex('by_subject', (q) =>
        q.eq('subject', args.subject).eq('tool', args.tool)
      )
      .unique();

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
