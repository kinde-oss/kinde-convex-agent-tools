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
    policy: {
      grant: FunctionReference<
        'mutation',
        'internal',
        {
          argumentConstraints?: Array<
            | {arg: string; kind: 'required'}
            | {arg: string; kind: 'min'; value: number}
            | {arg: string; kind: 'max'; value: number}
            | {
                arg: string;
                kind: 'denyValue';
                value: string | number | boolean;
              }
            | {
                arg: string;
                kind: 'allowValues';
                values: Array<string | number | boolean>;
              }
          > | null;
          risk?: 'low' | 'medium' | 'high' | null;
          subject: string;
          tool: string;
        },
        string,
        Name
      >;
      revokeGrant: FunctionReference<
        'mutation',
        'internal',
        {subject: string; tool: string},
        null,
        Name
      >;
      setToolRisk: FunctionReference<
        'mutation',
        'internal',
        {level: 'low' | 'medium' | 'high'; tool: string},
        string,
        Name
      >;
    };
  };
