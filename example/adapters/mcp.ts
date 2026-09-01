import {ConvexError} from 'convex/values';
import type {ToolArgs} from '@kinde-oss/kinde-convex-agent-tools';
import {gateOrThrow} from './governance.js';
import type {Governance} from './governance.js';

// --- Minimal MCP tool shape (typed locally; a genuine MCP tool handler
// registered with `McpServer.registerTool` satisfies it). No
// @modelcontextprotocol import, so nothing framework-specific is pulled in.
// MCP SDK 1.x calls a schema'd tool's handler with (args, extra): the input
// arrives FLAT as the first positional arg — already validated against the
// tool's declared `inputSchema`, with undeclared keys stripped — which the
// gate models as ToolArgs. The SDK's per-request extras (signal, sessionId,
// sendNotification, authInfo, …) arrive as the second arg and are preserved.
// A tool registered with NO `inputSchema` receives ONLY the extras object as
// its first arg — register no-arg tools with `inputSchema: {}` so the governed
// handler still sees flat (empty) args. These are `type` aliases (not
// interfaces) on purpose: the SDK's zod-inferred CallToolResult carries an
// index signature, and only object-literal type aliases are implicitly
// assignable to it under strict TS. ---
export type McpTextContent = {
  type: 'text';
  text: string;
};
export type McpToolResult = {
  content: McpTextContent[];
  isError?: boolean;
};
export type McpToolHandler<
  TArgs extends ToolArgs = ToolArgs,
  TExtra = unknown
> = (args: TArgs, extra?: TExtra) => Promise<McpToolResult>;

function mcpError(payload: Record<string, unknown>): McpToolResult {
  return {
    content: [{type: 'text', text: JSON.stringify(payload)}],
    isError: true
  };
}

/**
 * Wrap an MCP tool handler so every call routes through the gate BEFORE
 * dispatch. Adds no policy of its own:
 * - allow → run the real handler with the original (args, extra) preserved,
 *   so the SDK's per-request context is never dropped.
 * - deny → a structured MCP error (403-style, `isError:true`) naming the reason.
 * - approve → a structured MCP error carrying the `approvalId`.
 * The deny/approve mapping is NOT re-implemented here: it delegates to the
 * shared {@link gateOrThrow} (the single source of truth all adapters use) and
 * converts the thrown typed error's data — `{code, …}` minus the human-facing
 * `message` — into the structured MCP payload `{error: code, …}`. So the
 * decision, reasons and fields stay identical to `gate.checkTool`/the other
 * adapters by construction.
 */
export function governMcpTool<TArgs extends ToolArgs, TExtra = unknown>(
  gov: Governance & {toolName: string},
  handler: McpToolHandler<TArgs, TExtra>
): McpToolHandler<TArgs, TExtra> {
  return async (args, extra) => {
    try {
      await gateOrThrow(gov, gov.toolName, args);
    } catch (error) {
      if (error instanceof ConvexError) {
        const raw: unknown = error.data;
        const data: unknown =
          typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
        if (typeof data === 'object' && data !== null) {
          const record = data as Record<string, unknown>;
          // `code` becomes the payload's `error`; the human-facing `message`
          // is dropped; everything else (reason, approvalId, correlationId)
          // passes through unchanged.
          const payload: Record<string, unknown> = {error: record.code};
          for (const [key, value] of Object.entries(record)) {
            if (key !== 'code' && key !== 'message') {
              payload[key] = value;
            }
          }
          return mcpError(payload);
        }
      }
      throw error;
    }
    return await handler(args, extra);
  };
}
