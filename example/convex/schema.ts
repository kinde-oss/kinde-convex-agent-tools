import {defineSchema, defineTable} from 'convex/server';
import {v} from 'convex/values';

export default defineSchema({
  // Records each invocation of the example's fake billing check, so tests can
  // assert whether/what the tools spine sent to the billing seam (a real
  // invocation counter + payload capture — never raw args, only the digest).
  billingCalls: defineTable({
    subject: v.string(),
    tool: v.string(),
    argDigest: v.string(),
    correlationId: v.string()
  }),

  // Records each time a governed tool's real implementation actually EXECUTED
  // (the `fn` inside gate.runTool, or a post-approval execution). Lets the e2e
  // narrative prove a denied/approval-pending tool never ran, and an allowed one
  // did — an app-side side effect, distinct from the component's audit trail.
  toolRuns: defineTable({
    subject: v.string(),
    tool: v.string(),
    at: v.number()
  })
});
