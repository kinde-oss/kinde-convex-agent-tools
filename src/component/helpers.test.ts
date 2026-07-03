import {beforeEach, describe, expect, test, vi} from 'vitest';
import {ConvexError} from 'convex/values';
import {evaluateConstraints} from './helpers.js';
import type {ArgumentConstraint} from './validators.js';

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
const denyDelete: ArgumentConstraint = {
  arg: 'action',
  kind: 'denyValue',
  value: 'delete'
};

describe('evaluateConstraints', () => {
  test('no constraints → ok', () => {
    expect(evaluateConstraints([], {anything: 'goes'})).toEqual({ok: true});
  });

  test('max: within cap → ok; over cap → argument_denied', () => {
    expect(evaluateConstraints([maxAmount100], {amount: 50})).toEqual({
      ok: true
    });
    expect(evaluateConstraints([maxAmount100], {amount: 500})).toEqual({
      ok: false,
      reason: 'argument_denied'
    });
  });

  test('max: an absent arg does not apply', () => {
    expect(evaluateConstraints([maxAmount100], {other: 1})).toEqual({ok: true});
  });

  test('max: a non-numeric arg is a typed failure, never coerced', () => {
    expect(() => evaluateConstraints([maxAmount100], {amount: 'lots'})).toThrow(
      ConvexError
    );
  });

  test('denyValue: forbidden value denies; allowed value passes', () => {
    expect(evaluateConstraints([denyDelete], {action: 'delete'})).toEqual({
      ok: false,
      reason: 'argument_denied'
    });
    expect(evaluateConstraints([denyDelete], {action: 'read'})).toEqual({
      ok: true
    });
  });

  test('any single violated constraint denies the whole set', () => {
    expect(
      evaluateConstraints([maxAmount100, denyDelete], {
        amount: 10,
        action: 'delete'
      })
    ).toEqual({ok: false, reason: 'argument_denied'});
  });
});
