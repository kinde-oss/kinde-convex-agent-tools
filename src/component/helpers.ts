import {fail} from './errors.js';
import type {
  ArgumentConstraint,
  RevocationLevel,
  RiskLevel,
  ToolArgs
} from './validators.js';

// Revocation levels in precedence order, most → least broad. A higher level
// wins regardless of lower-level state (global > org > agent > grant).
const REVOCATION_PRECEDENCE: readonly RevocationLevel[] = [
  'global',
  'org',
  'agent',
  'grant'
];

/** The outcome of resolving the revocation overlay for one call. */
export type RevocationResolution =
  | {revoked: true; level: RevocationLevel}
  | {revoked: false};

/**
 * Given the set of levels at which an ACTIVE revocation applies to a call,
 * return whether the call is revoked and — if so — the HIGHEST-precedence level
 * that applies. Pure and exhaustive over the four levels: a higher level denies
 * regardless of lower-level state (global > org > agent > grant).
 */
export function resolveRevocation(
  presentLevels: Iterable<RevocationLevel>
): RevocationResolution {
  const present = new Set(presentLevels);
  for (const level of REVOCATION_PRECEDENCE) {
    if (present.has(level)) {
      return {revoked: true, level};
    }
  }
  return {revoked: false};
}

/**
 * The stable `targetId` key for a `grant`-level revocation: the (subject, tool)
 * pair encoded as `JSON.stringify([subject, tool])`. JSON encoding is
 * unambiguous for arbitrary subject/tool strings (no separator-collision), and
 * the spine computes the same key when checking the overlay, so a `grant`
 * revocation matches exactly the call it targets.
 */
export function grantRevocationKey(subject: string, tool: string): string {
  return JSON.stringify([subject, tool]);
}

// Ordering of risk levels, least → most strict. Used to pick the binding risk
// when a grant and a tool policy both declare one.
const RISK_ORDER: Record<RiskLevel, number> = {low: 0, medium: 1, high: 2};

/**
 * The effective risk for a call: the STRICTER (higher) of the grant's and the
 * tool policy's risk levels. Precedence is deliberately "most strict wins" so
 * neither source can weaken the other — a `high` policy is not softened by a
 * `low` grant, and vice versa. `null` on both sides means no risk gate applies.
 */
export function effectiveRisk(
  grantRisk: RiskLevel | null,
  policyRisk: RiskLevel | null
): RiskLevel | null {
  if (grantRisk === null) {
    return policyRisk;
  }
  if (policyRisk === null) {
    return grantRisk;
  }
  return RISK_ORDER[grantRisk] >= RISK_ORDER[policyRisk]
    ? grantRisk
    : policyRisk;
}

/**
 * Whether an effective risk requires human approval. THRESHOLD: only `high`
 * requires approval; `low`/`medium`/none pass straight through to allow. Kept
 * as its own predicate so the threshold is one documented, testable place.
 */
export function requiresApproval(risk: RiskLevel | null): boolean {
  return risk === 'high';
}

/**
 * The outcome of evaluating a set of argument constraints. A conclusive deny
 * carries the machine-readable `argument_denied` code; there is no "allow"
 * reason here — passing all constraints simply lets the decision continue.
 */
export type ConstraintOutcome =
  | {ok: true}
  | {ok: false; reason: 'argument_denied'};

/**
 * Reject a contradictory constraint SET before it is used or stored. Pure, and
 * about the constraints themselves (not the call's args), so it can run both at
 * grant time (fail fast) and at decision time (defense in depth):
 * - an `allowValues` with an empty set can never match → contradictory.
 * - a `min` and `max` on the same arg where `min > max` can never be satisfied.
 * Either is a typed `invalid_constraint` failure, never silently accepted.
 */
export function assertConstraintsWellFormed(
  constraints: readonly ArgumentConstraint[]
): void {
  // Largest floor and smallest ceiling per arg — the binding pair.
  const floors = new Map<string, number>();
  const ceilings = new Map<string, number>();
  for (const constraint of constraints) {
    if (constraint.kind === 'allowValues' && constraint.values.length === 0) {
      fail(
        'invalid_constraint',
        `Constraint 'allowValues' on '${constraint.arg}' must list at least one value.`
      );
    }
    if (constraint.kind === 'min') {
      const current = floors.get(constraint.arg);
      floors.set(
        constraint.arg,
        current === undefined
          ? constraint.value
          : Math.max(current, constraint.value)
      );
    } else if (constraint.kind === 'max') {
      const current = ceilings.get(constraint.arg);
      ceilings.set(
        constraint.arg,
        current === undefined
          ? constraint.value
          : Math.min(current, constraint.value)
      );
    }
  }
  for (const [arg, floor] of floors) {
    const ceiling = ceilings.get(arg);
    if (ceiling !== undefined && floor > ceiling) {
      fail(
        'invalid_constraint',
        `Constraint 'min' (${floor}) exceeds 'max' (${ceiling}) for argument '${arg}'.`
      );
    }
  }
}

/**
 * Evaluate argument constraints against a call's args. Pure. Deny-by-default
 * WITHIN the set: any single violated constraint denies the whole call. The
 * set is first checked for well-formedness (a contradictory set is a typed
 * failure, never coerced); then each kind applies its own absent-arg semantics
 * (see {@link ArgumentConstraint}). A `min`/`max` on a present NON-numeric arg
 * is a typed `invalid_argument` failure rather than a silent coercion.
 */
export function evaluateConstraints(
  constraints: readonly ArgumentConstraint[],
  args: ToolArgs
): ConstraintOutcome {
  assertConstraintsWellFormed(constraints);
  for (const constraint of constraints) {
    const value = args[constraint.arg];
    switch (constraint.kind) {
      case 'required':
        if (value === undefined || value === null) {
          return {ok: false, reason: 'argument_denied'};
        }
        break;
      case 'min':
        if (value === undefined || value === null) {
          break;
        }
        if (typeof value !== 'number') {
          fail(
            'invalid_argument',
            `Constraint 'min' on '${constraint.arg}' requires a numeric argument, got ${typeof value}.`
          );
        }
        if (value < constraint.value) {
          return {ok: false, reason: 'argument_denied'};
        }
        break;
      case 'max':
        if (value === undefined || value === null) {
          break;
        }
        if (typeof value !== 'number') {
          fail(
            'invalid_argument',
            `Constraint 'max' on '${constraint.arg}' requires a numeric argument, got ${typeof value}.`
          );
        }
        if (value > constraint.value) {
          return {ok: false, reason: 'argument_denied'};
        }
        break;
      case 'denyValue':
        if (value !== undefined && value === constraint.value) {
          return {ok: false, reason: 'argument_denied'};
        }
        break;
      case 'allowValues':
        if (value === undefined || value === null) {
          break;
        }
        if (Array.isArray(value) || !constraint.values.includes(value)) {
          return {ok: false, reason: 'argument_denied'};
        }
        break;
    }
  }
  return {ok: true};
}
