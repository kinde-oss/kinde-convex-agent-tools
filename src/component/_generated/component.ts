/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

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
    approvals: {
      approve: FunctionReference<
        "mutation",
        "internal",
        { approvalId: string; approver: string },
        null,
        Name
      >;
      deny: FunctionReference<
        "mutation",
        "internal",
        { approvalId: string; approver: string; reason: string },
        null,
        Name
      >;
      getStatus: FunctionReference<
        "query",
        "internal",
        { approvalId: string },
        {
          consumedAt: number | null;
          createdAt: number;
          expiresAt: number | null;
          resolvedAt: number | null;
          resolvedBy: string | null;
          resolvedReason: string | null;
          status: "pending" | "approved" | "denied" | "expired";
        } | null,
        Name
      >;
    };
    audit: {
      query: FunctionReference<
        "query",
        "internal",
        {
          correlationId?: string;
          decision?: "allow" | "deny" | "approve";
          paginationOpts: {
            cursor: string | null;
            endCursor?: string | null;
            id?: number;
            maximumBytesRead?: number;
            maximumRowsRead?: number;
            numItems: number;
          };
          subject?: string;
        },
        {
          continueCursor: string;
          isDone: boolean;
          page: Array<{
            _creationTime: number;
            _id: string;
            agent: string | null;
            argDigest: string;
            correlationId: string;
            decision: "allow" | "deny" | "approve";
            reason:
              | "granted"
              | "no_grant"
              | "argument_denied"
              | "revoked"
              | "budget_exceeded"
              | "approval_required"
              | "approval_approved"
              | "approval_denied"
              | "approval_consumed"
              | "executed"
              | null;
            subject: string;
            tool: string;
            ts: number;
          }>;
          pageStatus?: "SplitRecommended" | "SplitRequired" | null;
          splitCursor?: string | null;
        },
        Name
      >;
      recordCompletion: FunctionReference<
        "mutation",
        "internal",
        {
          args?: Record<
            string,
            string | number | boolean | null | Array<string>
          >;
          correlationId: string;
          subject: string;
          tool: string;
        },
        null,
        Name
      >;
    };
    enforce: {
      checkTool: FunctionReference<
        "mutation",
        "internal",
        {
          approvalTtlMs?: number;
          args?: Record<
            string,
            string | number | boolean | null | Array<string>
          >;
          billingCheck?: string;
          correlationId?: string | null;
          subject: string;
          tool: string;
        },
        {
          approvalId?: string;
          correlationId: string;
          decision: "allow" | "deny" | "approve";
          reason?:
            | "no_grant"
            | "argument_denied"
            | "revoked"
            | "budget_exceeded";
        },
        Name
      >;
    };
    policy: {
      grant: FunctionReference<
        "mutation",
        "internal",
        {
          argumentConstraints?: Array<
            | { arg: string; kind: "required" }
            | { arg: string; kind: "min"; value: number }
            | { arg: string; kind: "max"; value: number }
            | {
                arg: string;
                kind: "denyValue";
                value: string | number | boolean;
              }
            | {
                arg: string;
                kind: "allowValues";
                values: Array<string | number | boolean>;
              }
          > | null;
          risk?: "low" | "medium" | "high" | null;
          subject: string;
          tool: string;
        },
        string,
        Name
      >;
      revokeGrant: FunctionReference<
        "mutation",
        "internal",
        { subject: string; tool: string },
        null,
        Name
      >;
      setToolPolicy: FunctionReference<
        "mutation",
        "internal",
        {
          argumentConstraints?: Array<
            | { arg: string; kind: "required" }
            | { arg: string; kind: "min"; value: number }
            | { arg: string; kind: "max"; value: number }
            | {
                arg: string;
                kind: "denyValue";
                value: string | number | boolean;
              }
            | {
                arg: string;
                kind: "allowValues";
                values: Array<string | number | boolean>;
              }
          > | null;
          noArgs?: boolean;
          tool: string;
        },
        string,
        Name
      >;
      setToolRisk: FunctionReference<
        "mutation",
        "internal",
        { level: "low" | "medium" | "high"; tool: string },
        string,
        Name
      >;
    };
    revocations: {
      getStatus: FunctionReference<
        "query",
        "internal",
        {
          targetId?: string | null;
          targetType: "global" | "org" | "agent" | "grant";
        },
        {
          active: boolean;
          createdAt: number | null;
          reason: string | null;
          revokedBy: string | null;
        },
        Name
      >;
      liftRevocation: FunctionReference<
        "mutation",
        "internal",
        {
          targetId?: string | null;
          targetType: "global" | "org" | "agent" | "grant";
        },
        null,
        Name
      >;
      revoke: FunctionReference<
        "mutation",
        "internal",
        {
          reason: string;
          revokedBy?: string | null;
          targetId?: string | null;
          targetType: "global" | "org" | "agent" | "grant";
        },
        string,
        Name
      >;
    };
  };
