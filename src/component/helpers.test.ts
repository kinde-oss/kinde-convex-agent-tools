import {beforeEach, describe, expect, test, vi} from 'vitest';
import {ConvexError} from 'convex/values';
import {
  assertConstraintsWellFormed,
  effectiveRisk,
  evaluateConstraints,
  grantRevocationKey,
  parseBillingResult,
  requiresApproval,
  resolveRevocation
} from './helpers.js';
import type {ArgumentConstraint, RevocationLevel} from './validators.js';

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

const maxAmount100: ArgumentConstraint = {
  arg: 'amount',
  kind: 'max',
  value: 100
};
const minAmount10: ArgumentConstraint = {arg: 'amount', kind: 'min', value: 10};
const requireName: ArgumentConstraint = {arg: 'name', kind: 'required'};
const denyDelete: ArgumentConstraint = {
  arg: 'action',
  kind: 'denyValue',
  value: 'delete'
};
const allowReadWrite: ArgumentConstraint = {
  arg: 'action',
  kind: 'allowValues',
  values: ['read', 'write']
};

const ALLOW = {ok: true};
const DENY = {ok: false, reason: 'argument_denied'};

describe('evaluateConstraints — max', () => {
  test('within cap → allow; over cap → deny', () => {
    expect(evaluateConstraints([maxAmount100], {amount: 50})).toEqual(ALLOW);
    expect(evaluateConstraints([maxAmount100], {amount: 500})).toEqual(DENY);
  });
  test('absent arg does not apply', () => {
    expect(evaluateConstraints([maxAmount100], {other: 1})).toEqual(ALLOW);
  });
  test('non-numeric arg → typed fail (never coerced)', () => {
    expect(() => evaluateConstraints([maxAmount100], {amount: 'lots'})).toThrow(
      ConvexError
    );
  });
});

describe('evaluateConstraints — min', () => {
  test('at/above floor → allow; below floor → deny', () => {
    expect(evaluateConstraints([minAmount10], {amount: 10})).toEqual(ALLOW);
    expect(evaluateConstraints([minAmount10], {amount: 3})).toEqual(DENY);
  });
  test('absent arg does not apply', () => {
    expect(evaluateConstraints([minAmount10], {other: 1})).toEqual(ALLOW);
  });
  test('non-numeric arg → typed fail (never coerced)', () => {
    expect(() => evaluateConstraints([minAmount10], {amount: 'few'})).toThrow(
      ConvexError
    );
  });
});

describe('evaluateConstraints — required', () => {
  test('present non-null → allow', () => {
    expect(evaluateConstraints([requireName], {name: 'ada'})).toEqual(ALLOW);
  });
  test('absent → deny (closes the omit-the-arg dodge)', () => {
    expect(evaluateConstraints([requireName], {other: 1})).toEqual(DENY);
  });
  test('present but null → deny', () => {
    expect(evaluateConstraints([requireName], {name: null})).toEqual(DENY);
  });
});

describe('evaluateConstraints — denyValue', () => {
  test('forbidden value → deny; other value → allow; absent → allow', () => {
    expect(evaluateConstraints([denyDelete], {action: 'delete'})).toEqual(DENY);
    expect(evaluateConstraints([denyDelete], {action: 'read'})).toEqual(ALLOW);
    expect(evaluateConstraints([denyDelete], {other: 1})).toEqual(ALLOW);
  });
});

describe('evaluateConstraints — allowValues', () => {
  test('in set → allow; out of set → deny', () => {
    expect(evaluateConstraints([allowReadWrite], {action: 'read'})).toEqual(
      ALLOW
    );
    expect(evaluateConstraints([allowReadWrite], {action: 'delete'})).toEqual(
      DENY
    );
  });
  test('absent + not required → allow', () => {
    expect(evaluateConstraints([allowReadWrite], {other: 1})).toEqual(ALLOW);
  });
  test('required + allowValues forces presence AND membership', () => {
    const constraints: ArgumentConstraint[] = [
      {arg: 'action', kind: 'required'},
      allowReadWrite
    ];
    expect(evaluateConstraints(constraints, {other: 1})).toEqual(DENY);
    expect(evaluateConstraints(constraints, {action: 'write'})).toEqual(ALLOW);
  });
});

describe('evaluateConstraints — set semantics', () => {
  test('any single violation denies the whole set', () => {
    expect(
      evaluateConstraints([maxAmount100, denyDelete], {
        amount: 10,
        action: 'delete'
      })
    ).toEqual(DENY);
  });
  test('all-satisfied set → allow', () => {
    expect(
      evaluateConstraints([minAmount10, maxAmount100, allowReadWrite], {
        amount: 50,
        action: 'read'
      })
    ).toEqual(ALLOW);
  });
});

describe('assertConstraintsWellFormed — contradictions', () => {
  test('empty allowValues → typed fail', () => {
    expect(() =>
      assertConstraintsWellFormed([{arg: 'x', kind: 'allowValues', values: []}])
    ).toThrow(ConvexError);
    // and via the evaluator path too
    expect(() =>
      evaluateConstraints([{arg: 'x', kind: 'allowValues', values: []}], {})
    ).toThrow(ConvexError);
  });
  test('min > max on the same arg → typed fail', () => {
    const contradictory: ArgumentConstraint[] = [
      {arg: 'amount', kind: 'min', value: 100},
      {arg: 'amount', kind: 'max', value: 10}
    ];
    expect(() => assertConstraintsWellFormed(contradictory)).toThrow(
      ConvexError
    );
    expect(() => evaluateConstraints(contradictory, {amount: 50})).toThrow(
      ConvexError
    );
  });
  test('min <= max on the same arg is fine', () => {
    expect(() =>
      assertConstraintsWellFormed([minAmount10, maxAmount100])
    ).not.toThrow();
  });
  test('min and max on DIFFERENT args never contradict', () => {
    expect(() =>
      assertConstraintsWellFormed([
        {arg: 'a', kind: 'min', value: 100},
        {arg: 'b', kind: 'max', value: 10}
      ])
    ).not.toThrow();
  });
});

describe('effectiveRisk — stricter (higher) wins', () => {
  test('null on both → null (no risk gate)', () => {
    expect(effectiveRisk(null, null)).toBeNull();
  });
  test('one side null → the other', () => {
    expect(effectiveRisk('high', null)).toBe('high');
    expect(effectiveRisk(null, 'medium')).toBe('medium');
  });
  test('both set → the stricter one', () => {
    expect(effectiveRisk('low', 'high')).toBe('high');
    expect(effectiveRisk('high', 'low')).toBe('high');
    expect(effectiveRisk('medium', 'low')).toBe('medium');
    expect(effectiveRisk('medium', 'medium')).toBe('medium');
  });
});

describe('requiresApproval — threshold is high', () => {
  test('only high requires approval', () => {
    expect(requiresApproval('high')).toBe(true);
    expect(requiresApproval('medium')).toBe(false);
    expect(requiresApproval('low')).toBe(false);
    expect(requiresApproval(null)).toBe(false);
  });
});

describe('resolveRevocation — precedence global > org > agent > grant', () => {
  test('no levels present → not revoked', () => {
    expect(resolveRevocation([])).toEqual({revoked: false});
  });

  test('a single level present → revoked at that level', () => {
    const levels: RevocationLevel[] = ['global', 'org', 'agent', 'grant'];
    for (const level of levels) {
      expect(resolveRevocation([level])).toEqual({revoked: true, level});
    }
  });

  test('highest present wins for every pair', () => {
    expect(resolveRevocation(['grant', 'agent'])).toEqual({
      revoked: true,
      level: 'agent'
    });
    expect(resolveRevocation(['grant', 'org'])).toEqual({
      revoked: true,
      level: 'org'
    });
    expect(resolveRevocation(['agent', 'org'])).toEqual({
      revoked: true,
      level: 'org'
    });
    expect(resolveRevocation(['grant', 'agent', 'org', 'global'])).toEqual({
      revoked: true,
      level: 'global'
    });
  });

  test('order of the input does not matter (set semantics)', () => {
    expect(resolveRevocation(['agent', 'grant'])).toEqual(
      resolveRevocation(['grant', 'agent'])
    );
  });

  test('exhaustive: global dominates every combination it appears in', () => {
    const combos: RevocationLevel[][] = [
      ['global'],
      ['global', 'grant'],
      ['global', 'agent', 'grant'],
      ['global', 'org', 'agent', 'grant']
    ];
    for (const combo of combos) {
      expect(resolveRevocation(combo)).toEqual({
        revoked: true,
        level: 'global'
      });
    }
  });
});

describe('grantRevocationKey — stable (subject, tool) encoding', () => {
  test('is deterministic and unambiguous', () => {
    expect(grantRevocationKey('user_alice', 'search')).toBe(
      grantRevocationKey('user_alice', 'search')
    );
    // Distinct pairs never collide, even across the boundary.
    expect(grantRevocationKey('a', 'bc')).not.toBe(
      grantRevocationKey('ab', 'c')
    );
  });
});

describe('parseBillingResult — untrusted billing return is validated', () => {
  test('accepts a well-formed allow/deny result', () => {
    expect(parseBillingResult({allow: true})).toEqual({allow: true});
    expect(parseBillingResult({allow: false, reason: 'nope'})).toEqual({
      allow: false,
      reason: 'nope'
    });
  });

  test('drops an undefined reason cleanly', () => {
    expect(parseBillingResult({allow: true, reason: undefined})).toEqual({
      allow: true
    });
  });

  test('a non-object return → typed billing_check_malformed', () => {
    for (const bad of [null, undefined, 42, 'nope', true]) {
      expect(() => parseBillingResult(bad)).toThrow(ConvexError);
    }
  });

  test('a missing or non-boolean allow → typed billing_check_malformed', () => {
    expect(() => parseBillingResult({})).toThrow(ConvexError);
    expect(() => parseBillingResult({allow: 'yes'})).toThrow(ConvexError);
    expect(() => parseBillingResult({ok: 1})).toThrow(ConvexError);
  });

  test('a non-string reason → typed billing_check_malformed', () => {
    expect(() => parseBillingResult({allow: false, reason: 5})).toThrow(
      ConvexError
    );
  });
});
