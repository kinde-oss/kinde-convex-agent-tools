/// <reference types="vite/client" />
import {beforeEach, expect, test, vi} from 'vitest';
import {convexTest} from 'convex-test';
import type {TestConvex} from 'convex-test';
import {defineSchema} from 'convex/server';
import type {
  FunctionReference,
  FunctionVisibility,
  GenericSchema,
  SchemaDefinition
} from 'convex/server';
import {ConvexError} from 'convex/values';
import type {Value} from 'convex/values';
import {register} from '../test.js';
import {parseJson} from '../component/errors.js';
import {readEnv} from '../component/env.js';
import type {RunFullCtx} from './index.js';

const modules = import.meta.glob('./**/*.*s');

// Stub the component's env before every test. MODE is the only var it reads.
beforeEach(() => {
  vi.stubEnv('MODE', 'test');
});

/** Boot an app-side convexTest instance with the component registered. */
export function initConvexTest() {
  const t = convexTest(defineSchema({}), modules);
  register(t);
  return t;
}

type Args = Record<string, unknown>;

/**
 * Adapt a TestConvex instance to the ctx shape the client layer expects,
 * mirroring how an app action would call into the component.
 */
export function makeRunCtx(
  t: TestConvex<SchemaDefinition<GenericSchema, boolean>>
): RunFullCtx {
  const runQuery = async (
    ref: FunctionReference<'query', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.query(ref, args ?? {});
  const runMutation = async (
    ref: FunctionReference<'mutation', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.mutation(ref, args ?? {});
  const runAction = async (
    ref: FunctionReference<'action', FunctionVisibility>,
    args?: Args
  ): Promise<unknown> => await t.action(ref, args ?? {});
  return {
    runQuery: runQuery as RunFullCtx['runQuery'],
    runMutation: runMutation as RunFullCtx['runMutation'],
    runAction: runAction as RunFullCtx['runAction']
  };
}

/**
 * Assert that a call rejects with a machine-readable ConvexError carrying the
 * given `code`. Handles both object data (errors thrown in-process) and
 * JSON-string data (errors re-serialized by convex-test across the boundary).
 */
export async function expectFail(
  promise: Promise<unknown>,
  code: string
): Promise<void> {
  let error: unknown;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  expect(error, `expected ConvexError with code "${code}"`).toBeInstanceOf(
    ConvexError
  );
  const raw = (error as ConvexError<Value>).data;
  const data = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
  expect((data as {code: string}).code).toBe(code);
}

test('component boots via register()', async () => {
  const t = initConvexTest();
  // Prove the harness actually spins up with the component registered.
  const ok = await t.run(async () => 'ok');
  expect(ok).toBe('ok');
});

test('readEnv validates the MODE enum', () => {
  expect(readEnv()).toEqual({mode: 'test'});

  // Outside the enum is a hard failure, never a silent fallback to the default.
  vi.stubEnv('MODE', 'bogus');
  expect(() => readEnv()).toThrow(ConvexError);

  // Unset → the documented `live` default.
  vi.stubEnv('MODE', '');
  expect(readEnv()).toEqual({mode: 'live'});
});

test('parseJson maps a non-JSON body to a typed failure', () => {
  expect(parseJson<{a: number}>('{"a":1}')).toEqual({a: 1});
  expect(() => parseJson('not json', 'invalid_tool_args')).toThrow(ConvexError);
});
