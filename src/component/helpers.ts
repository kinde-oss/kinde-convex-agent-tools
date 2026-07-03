import {fail} from './errors.js';
import type {ArgumentConstraint, ToolArgs} from './validators.js';

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
