import {v} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import type {MutationCtx, QueryCtx} from './_generated/server.js';
import {fail} from './errors.js';
import {grantRevocationKey} from './helpers.js';
import {
  nullableNumber,
  nullableString,
  revocationLevelValidator
} from './validators.js';
import type {RevocationLevel} from './validators.js';

/**
 * Validate a revocation target and return its canonical `targetId`. A `global`
 * revocation MUST NOT carry a targetId (it revokes everything); every other
 * level MUST carry a non-empty one. A contradictory pairing (global-with-id, or
 * a scoped level without an id) is a typed `invalid_target` failure, never
 * coerced.
 */
function normalizeTarget(
  targetType: RevocationLevel,
  targetId: string | null
): string | null {
  if (targetType === 'global') {
    if (targetId !== null) {
      fail(
        'invalid_target',
        "A 'global' revocation must not carry a targetId."
      );
    }
    return null;
  }
  if (targetId === null || targetId.length === 0) {
    fail('invalid_target', `A '${targetType}' revocation requires a targetId.`);
  }
  return targetId;
}

/** The active revocation row for (targetType, targetId), or null. */
async function activeRow(
  ctx: QueryCtx,
  targetType: RevocationLevel,
  targetId: string | null
) {
  const row = await ctx.db
    .query('revocations')
    .withIndex('by_target', (q) =>
      q.eq('targetType', targetType).eq('targetId', targetId)
    )
    .unique();
  return row !== null && row.active ? row : null;
}

/**
 * Gather the levels at which an ACTIVE revocation applies to a call's identity.
 * Only the levels reachable in the current identity model are queried: `global`
 * (always) and `grant` (always — the (subject, tool) key). `agent` is queried
 * only when a non-null agent is supplied, and `org` only when an org is — both
 * are structurally supported now and exercised once those identities land. The
 * pure `resolveRevocation` then picks the highest-precedence level present.
 */
export async function activeRevocationLevels(
  ctx: QueryCtx,
  identity: {
    subject: string;
    tool: string;
    agent: string | null;
    org: string | null;
  }
): Promise<RevocationLevel[]> {
  const levels: RevocationLevel[] = [];
  if ((await activeRow(ctx, 'global', null)) !== null) {
    levels.push('global');
  }
  if (
    identity.org !== null &&
    (await activeRow(ctx, 'org', identity.org)) !== null
  ) {
    levels.push('org');
  }
  if (
    identity.agent !== null &&
    (await activeRow(ctx, 'agent', identity.agent)) !== null
  ) {
    levels.push('agent');
  }
  const grantKey = grantRevocationKey(identity.subject, identity.tool);
  if ((await activeRow(ctx, 'grant', grantKey)) !== null) {
    levels.push('grant');
  }
  return levels;
}

async function findAnyRow(
  ctx: MutationCtx,
  targetType: RevocationLevel,
  targetId: string | null
) {
  return await ctx.db
    .query('revocations')
    .withIndex('by_target', (q) =>
      q.eq('targetType', targetType).eq('targetId', targetId)
    )
    .unique();
}

/**
 * Revoke a target (create the overlay row, or reactivate a previously-lifted
 * one). NON-DESTRUCTIVE: it never touches the grant — the next `checkTool`
 * re-queries the overlay and denies `revoked`. Re-revoking an ALREADY-ACTIVE
 * target is a typed `already_revoked` failure (fail-fast, never a silent
 * overwrite); a previously-lifted (inactive) row is reused and reactivated.
 */
export const revoke = mutation({
  args: {
    targetType: revocationLevelValidator,
    targetId: v.optional(nullableString),
    reason: v.string(),
    revokedBy: v.optional(nullableString)
  },
  returns: v.id('revocations'),
  handler: async (ctx, args) => {
    const targetId = normalizeTarget(args.targetType, args.targetId ?? null);
    const revokedBy = args.revokedBy ?? null;
    const now = Date.now();

    const existing = await findAnyRow(ctx, args.targetType, targetId);
    if (existing !== null) {
      if (existing.active) {
        fail(
          'already_revoked',
          `A '${args.targetType}' revocation is already active for this target.`
        );
      }
      await ctx.db.patch('revocations', existing._id, {
        reason: args.reason,
        revokedBy,
        active: true,
        createdAt: now
      });
      return existing._id;
    }
    return await ctx.db.insert('revocations', {
      targetType: args.targetType,
      targetId,
      reason: args.reason,
      revokedBy,
      active: true,
      createdAt: now
    });
  }
});

/**
 * Lift a revocation (flip `active` to false; the grant is untouched). Lifting a
 * target that is not currently revoked is a typed `not_revoked` failure — the
 * same fail-fast discipline as `policy.revokeGrant`, so a caller can never think
 * it lifted something it didn't.
 */
export const liftRevocation = mutation({
  args: {
    targetType: revocationLevelValidator,
    targetId: v.optional(nullableString)
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const targetId = normalizeTarget(args.targetType, args.targetId ?? null);
    const existing = await findAnyRow(ctx, args.targetType, targetId);
    if (existing === null || !existing.active) {
      fail(
        'not_revoked',
        `No active '${args.targetType}' revocation to lift for this target.`
      );
    }
    await ctx.db.patch('revocations', existing._id, {active: false});
    return null;
  }
});

/** Read-only: is this target currently revoked, and with what metadata. */
export const getStatus = query({
  args: {
    targetType: revocationLevelValidator,
    targetId: v.optional(nullableString)
  },
  returns: v.object({
    active: v.boolean(),
    reason: nullableString,
    revokedBy: nullableString,
    createdAt: nullableNumber
  }),
  handler: async (ctx, args) => {
    const targetId = normalizeTarget(args.targetType, args.targetId ?? null);
    const row = await activeRow(ctx, args.targetType, targetId);
    if (row === null) {
      return {active: false, reason: null, revokedBy: null, createdAt: null};
    }
    return {
      active: true,
      reason: row.reason,
      revokedBy: row.revokedBy,
      createdAt: row.createdAt
    };
  }
});
