/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as example from '../example.js';
import type * as fakeBilling from '../fakeBilling.js';
import type * as http from '../http.js';
import type * as mcpLive from '../mcpLive.js';

import type {ApiFromModules, FilterApi, FunctionReference} from 'convex/server';

declare const fullApi: ApiFromModules<{
  example: typeof example;
  fakeBilling: typeof fakeBilling;
  http: typeof http;
  mcpLive: typeof mcpLive;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, 'public'>
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, 'internal'>
>;

export declare const components: {
  tools: import('@kinde-oss/kinde-convex-agent-tools/_generated/component.js').ComponentApi<'tools'>;
};
