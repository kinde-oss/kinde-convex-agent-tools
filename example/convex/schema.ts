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
  })
});
