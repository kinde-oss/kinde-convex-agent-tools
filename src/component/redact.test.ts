import {beforeEach, describe, expect, test, vi} from 'vitest';
import {redactArgs} from './redact.js';

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

describe('redactArgs', () => {
  const SECRET = 'sk-super-secret-value-1234';

  test('drops raw values: a secret-looking value never appears verbatim', () => {
    const digest = redactArgs({apiKey: SECRET, count: 42, live: true});
    expect(digest).not.toContain(SECRET);
    expect(digest).not.toContain('42');
    // Argument NAMES are schema, not secrets, so they are preserved.
    expect(digest).toContain('apiKey');
    expect(digest).toContain('count');
  });

  test('is stable: identical args produce identical digests', () => {
    expect(redactArgs({a: 'x', b: 1})).toBe(redactArgs({a: 'x', b: 1}));
  });

  test('is key-order independent', () => {
    expect(redactArgs({a: 'x', b: 1})).toBe(redactArgs({b: 1, a: 'x'}));
  });

  test('distinguishes different values', () => {
    expect(redactArgs({a: 'x'})).not.toBe(redactArgs({a: 'y'}));
  });

  test('handles nulls and string arrays without leaking contents', () => {
    const digest = redactArgs({maybe: null, tags: ['alpha', 'beta']});
    expect(digest).not.toContain('alpha');
    expect(digest).not.toContain('beta');
    expect(digest).toContain('null');
  });
});
