/// <reference types="vite/client" />
import {beforeEach, expect, test, vi} from 'vitest';
import {convexTest} from 'convex-test';
import {api} from './_generated/api.js';
import schema from './schema.js';
import component from '@kinde-oss/kinde-convex-agent-tools/test';

const modules = import.meta.glob('./**/*.*s');

// Hardening: stub ALL required component env vars before every test.
beforeEach(() => {
  vi.stubEnv('TOOLS_SIGNING_SECRET', 'test-signing-secret');
  vi.stubEnv('MODE', 'test');
});

// When users want to write tests that use the component, they need to
// explicitly register it with its schema and modules.
export function initConvexTest() {
  const t = convexTest(schema, modules);
  component.register(t);
  return t;
}

test('example app loads with the component mounted', async () => {
  const t = initConvexTest();
  expect(await t.query(api.example.health, {})).toBe('ok');
});
