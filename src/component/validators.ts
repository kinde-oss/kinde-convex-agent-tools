import {v} from 'convex/values';
import type {Infer} from 'convex/values';

/**
 * A tool-call decision. Two-valued in P1: `allow` or `deny`. The
 * `require-human-approval` outcome arrives with the approval gate in P3, so it
 * is deliberately absent here rather than stubbed.
 */
export const decisionValidator = v.union(v.literal('allow'), v.literal('deny'));

/** A tool's risk level. Carried on grants/policies; consumed by the P3 gate. */
export const riskLevelValidator = v.union(
  v.literal('low'),
  v.literal('medium'),
  v.literal('high')
);

/**
 * The machine-readable reason a call was DENIED. This is the P1 `DenyCode`
 * union surfaced on a deny decision; it grows as later phases add deny paths
 * (budget, risk, revocation). Never free text.
 */
export const denyCodeValidator = v.union(
  v.literal('no_grant'),
  v.literal('argument_denied')
);

/**
 * The machine-readable reason stamped on EVERY audit/toolCalls row — the deny
 * codes plus the positive `granted`. Every decision carries one (audit
 * completeness), so this is a superset of {@link denyCodeValidator}.
 */
export const reasonCodeValidator = v.union(
  v.literal('granted'),
  v.literal('no_grant'),
  v.literal('argument_denied')
);

/**
 * A single argument-level constraint. MINIMAL in P1 — just enough to prove
 * argument-level denial end to end (the full constraint DSL is P2):
 * - `max`: deny when the numeric arg exceeds `value`.
 * - `denyValue`: deny when the arg exactly equals `value`.
 * The shape is a discriminated union, so an ill-typed constraint (e.g. a `max`
 * with a non-numeric `value`) cannot even be stored.
 */
export const argumentConstraintValidator = v.union(
  v.object({
    arg: v.string(),
    kind: v.literal('max'),
    value: v.number()
  }),
  v.object({
    arg: v.string(),
    kind: v.literal('denyValue'),
    value: v.union(v.string(), v.number(), v.boolean())
  })
);

/**
 * A tool call's arguments: a flat, string-keyed record of JSON-ish primitives
 * and string arrays. Flat by design so the whole value stays fully typed (no
 * `any`) and is cheaply, deterministically redactable for the audit digest.
 */
export const argsValidator = v.record(
  v.string(),
  v.union(v.string(), v.number(), v.boolean(), v.null(), v.array(v.string()))
);

export const nullableString = v.union(v.string(), v.null());
export const nullableNumber = v.union(v.number(), v.null());

export type Decision = Infer<typeof decisionValidator>;
export type RiskLevel = Infer<typeof riskLevelValidator>;
export type DenyCode = Infer<typeof denyCodeValidator>;
export type ReasonCode = Infer<typeof reasonCodeValidator>;
export type ArgumentConstraint = Infer<typeof argumentConstraintValidator>;
export type ToolArgs = Infer<typeof argsValidator>;
export type ToolArgValue = ToolArgs[string];
