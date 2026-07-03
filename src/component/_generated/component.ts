/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type {FunctionReference} from 'convex/server';

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    enforce: {
      checkTool: FunctionReference<
        'mutation',
        'internal',
        {
          args?: Record<
            string,
            string | number | boolean | null | Array<string>
          >;
          correlationId?: string | null;
          subject: string;
          tool: string;
        },
        {
          correlationId: string;
          decision: 'allow' | 'deny';
          reason?: 'no_grant' | 'argument_denied';
        },
        Name
      >;
    };
  };
