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
 * Evaluate argument constraints against a call's args. Pure. Deny-by-default
 * WITHIN the set: any single violated constraint denies the whole call.
 *
 * - `max`: an absent arg does not apply (nothing to cap); a present numeric arg
 *   over `value` denies. A present NON-numeric arg cannot be compared without
 *   coercion, so it is a typed `invalid_argument` failure — never silently
 *   coerced (HARDENING).
 * - `denyValue`: a present arg exactly equal to `value` denies; anything else
 *   (including absent) passes.
 */
export function evaluateConstraints(
  constraints: readonly ArgumentConstraint[],
  args: ToolArgs
): ConstraintOutcome {
  for (const constraint of constraints) {
    const value = args[constraint.arg];
    if (constraint.kind === 'max') {
      if (value === undefined || value === null) {
        continue;
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
    } else {
      if (value !== undefined && value === constraint.value) {
        return {ok: false, reason: 'argument_denied'};
      }
    }
  }
  return {ok: true};
}
