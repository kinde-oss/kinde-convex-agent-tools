import {v} from 'convex/values';
import {mutation, query} from './_generated/server.js';
import type {MutationCtx} from './_generated/server.js';
import type {Id} from './_generated/dataModel.js';
import {fail} from './errors.js';
import {
  approvalStatusValidator,
  nullableNumber,
  nullableString
} from './validators.js';

/**
 * Resolve a pending approval to `approved` or `denied`. The APP authenticates
 * the human approver; the component takes `approver` as a trusted identity
 * string (same trust model as `subject`). Guards, in order:
 *  - the approver identity must be non-empty;
 *  - the approval must exist;
 *  - a pending approval past its `expiresAt` is `expired` and can no longer be
 *    resolved (typed `approval_expired`); expiry is computed here, never stored;
 *  - only a `pending` approval may be resolved — re-resolving a terminal one is
 *    a typed `approval_not_pending`, never a silent overwrite.
 * On success it records `resolvedBy`/`resolvedAt` and APPENDS a distinct audit
 * row for the resolution event (decision stays `approve`; the reason —
 * `approval_approved` / `approval_denied` — distinguishes it from the original
 * `approval_required` decision row, so the one-decision-row invariant holds).
 */
async function resolve(
  ctx: MutationCtx,
  approvalId: Id<'approvals'>,
  approver: string,
  target: 'approved' | 'denied',
  reason: string | null
): Promise<null> {
  if (approver.length === 0) {
    fail('approver_required', 'approver is required to resolve an approval.');
  }
  const approval = await ctx.db.get('approvals', approvalId);
  if (approval === null) {
    fail('approval_not_found', 'No such approval.');
  }
  const now = Date.now();
  if (
    approval.status === 'pending' &&
    approval.expiresAt !== null &&
    approval.expiresAt < now
  ) {
    fail(
      'approval_expired',
      'This approval has expired and can no longer be resolved.'
    );
  }
  if (approval.status !== 'pending') {
    fail(
      'approval_not_pending',
      `Approval is "${approval.status}", not "pending".`
    );
  }
  await ctx.db.patch('approvals', approvalId, {
    status: target,
    resolvedBy: approver,
    resolvedAt: now,
    resolvedReason: reason
  });
  await ctx.db.insert('audit', {
    subject: approval.subject,
    agent: approval.agent,
    tool: approval.tool,
    argDigest: approval.argDigest,
    decision: 'approve',
    reason: target === 'approved' ? 'approval_approved' : 'approval_denied',
    correlationId: approval.correlationId,
    ts: now
  });
  return null;
}

/** Approve a pending approval (pending → approved). */
export const approve = mutation({
  args: {
    approvalId: v.id('approvals'),
    approver: v.string()
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    return await resolve(ctx, args.approvalId, args.approver, 'approved', null);
  }
});

/** Deny a pending approval (pending → denied), recording the human's reason. */
export const deny = mutation({
  args: {
    approvalId: v.id('approvals'),
    approver: v.string(),
    reason: v.string()
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    return await resolve(
      ctx,
      args.approvalId,
      args.approver,
      'denied',
      args.reason
    );
  }
});

const statusResultValidator = v.object({
  status: approvalStatusValidator,
  resolvedBy: nullableString,
  resolvedAt: nullableNumber,
  resolvedReason: nullableString,
  expiresAt: nullableNumber,
  createdAt: v.number()
});

/**
 * Read-only status of an approval. Expiry is LAZY: a stored `pending` row whose
 * `expiresAt` has passed is REPORTED as `expired` (never persisted), so a
 * reader and a resolver agree on the same instant.
 */
export const getStatus = query({
  args: {approvalId: v.id('approvals')},
  returns: v.union(statusResultValidator, v.null()),
  handler: async (ctx, args) => {
    const approval = await ctx.db.get('approvals', args.approvalId);
    if (approval === null) {
      return null;
    }
    const now = Date.now();
    const status =
      approval.status === 'pending' &&
      approval.expiresAt !== null &&
      approval.expiresAt < now
        ? 'expired'
        : approval.status;
    return {
      status,
      resolvedBy: approval.resolvedBy,
      resolvedAt: approval.resolvedAt,
      resolvedReason: approval.resolvedReason,
      expiresAt: approval.expiresAt,
      createdAt: approval.createdAt
    };
  }
});
