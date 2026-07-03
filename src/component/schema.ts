import {defineSchema} from 'convex/server';

/**
 * The component schema. Empty for now — the tables (allowlist rules, approval
 * requests, and the append-only audit log) land in P1.
 *
 * Nothing here precludes the invariants: deny-by-default, decision atomicity,
 * argument-level enforcement, reactive revocation, the approval gate, and audit
 * completeness/redaction all sit on top of tables added later. This empty
 * schema keeps the harness bootable in P0 without committing to a shape early.
 */
export default defineSchema({});
