import {beforeEach, describe, expect, test, vi} from 'vitest';
import {argBindingDigest} from './digest.js';

// Stub the component's env before every test. MODE is the only var it reads.
beforeEach(() => {
  vi.stubEnv('MODE', 'test');
});

describe('argBindingDigest', () => {
  test('is stable: identical args produce identical digests', async () => {
    expect(await argBindingDigest({a: 'x', b: 1})).toBe(
      await argBindingDigest({a: 'x', b: 1})
    );
  });

  test('is key-order independent (canonical ordering)', async () => {
    expect(await argBindingDigest({a: 'x', b: 1})).toBe(
      await argBindingDigest({b: 1, a: 'x'})
    );
  });

  test('different args produce different digests', async () => {
    expect(await argBindingDigest({a: 'x'})).not.toBe(
      await argBindingDigest({a: 'y'})
    );
    // A different KEY is a different call, even at the same value.
    expect(await argBindingDigest({a: 'x'})).not.toBe(
      await argBindingDigest({b: 'x'})
    );
    // Type is part of the binding: "1" is not 1.
    expect(await argBindingDigest({a: '1'})).not.toBe(
      await argBindingDigest({a: 1})
    );
    // Absent is not null.
    expect(await argBindingDigest({})).not.toBe(
      await argBindingDigest({a: null})
    );
  });

  test('separators in a value cannot forge another args encoding', async () => {
    // The canonical form is JSON, so a value carrying the delimiters cannot
    // impersonate a second argument.
    expect(await argBindingDigest({a: 'x","b":"y'})).not.toBe(
      await argBindingDigest({a: 'x', b: 'y'})
    );
  });

  test('is real SHA-256, hex, version-tagged', async () => {
    const digest = await argBindingDigest({a: 'x'});
    expect(digest).toMatch(/^v1:sha256:[0-9a-f]{64}$/);
    // Pinned against an independently computed SHA-256 of the canonical form,
    // so a change to the canonicalization cannot pass unnoticed.
    const expected = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('[["a","x"]]')
    );
    const hex = [...new Uint8Array(expected)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    expect(digest).toBe(`v1:sha256:${hex}`);
  });
});
