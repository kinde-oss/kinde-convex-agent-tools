import {mutation} from './_generated/server.js';
import type {MutationCtx} from './_generated/server.js';
import {v} from 'convex/values';
import {
  billingCheckPayloadValidator,
  billingCheckResultValidator
} from '@kinde-oss/kinde-convex-agent-tools';

// EXAMPLE ONLY — fake billing checks used by the tests to exercise the P5
// billing seam WITHOUT importing the real billing package. Each mirrors the
// shape a real app would expose: it receives the shared, REDACTED payload and
// returns the shared result shape. They record every invocation into
// `billingCalls` so tests can count calls and inspect the (redacted) payload.
const payload = billingCheckPayloadValidator.fields;

async function record(
  ctx: MutationCtx,
  args: {
    subject: string;
    tool: string;
    argDigest: string;
    correlationId: string;
  }
): Promise<void> {
  await ctx.db.insert('billingCalls', {
    subject: args.subject,
    tool: args.tool,
    argDigest: args.argDigest,
    correlationId: args.correlationId
  });
}

/** Approves every call. */
export const billingAllow = mutation({
  args: payload,
  returns: billingCheckResultValidator,
  handler: async (ctx, args) => {
    await record(ctx, args);
    return {allow: true};
  }
});

/** Denies every call (simulates an exhausted budget). */
export const billingDeny = mutation({
  args: payload,
  returns: billingCheckResultValidator,
  handler: async (ctx, args) => {
    await record(ctx, args);
    return {allow: false, reason: 'over budget'};
  }
});

/** Returns a MALFORMED shape (no boolean `allow`) to exercise the hardening. */
export const billingMalformed = mutation({
  args: payload,
  returns: v.object({ok: v.number()}),
  handler: async (ctx, args) => {
    await record(ctx, args);
    return {ok: 1};
  }
});
