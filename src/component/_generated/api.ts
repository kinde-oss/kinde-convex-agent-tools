/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as approvals from '../approvals.js';
import type * as audit from '../audit.js';
import type * as enforce from '../enforce.js';
import type * as env from '../env.js';
import type * as errors from '../errors.js';
import type * as helpers from '../helpers.js';
import type * as policy from '../policy.js';
import type * as redact from '../redact.js';
import type * as revocations from '../revocations.js';
import type * as validators from '../validators.js';

import type {ApiFromModules, FilterApi, FunctionReference} from 'convex/server';
import {anyApi, componentsGeneric} from 'convex/server';

const fullApi: ApiFromModules<{
  approvals: typeof approvals;
  audit: typeof audit;
  enforce: typeof enforce;
  env: typeof env;
  errors: typeof errors;
  helpers: typeof helpers;
  policy: typeof policy;
  redact: typeof redact;
  revocations: typeof revocations;
  validators: typeof validators;
}> = anyApi as any;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, 'public'>
> = anyApi as any;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, 'internal'>
> = anyApi as any;

export const components = componentsGeneric() as unknown as {};
