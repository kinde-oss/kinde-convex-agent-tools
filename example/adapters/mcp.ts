import type {ToolArgs} from '@kinde-oss/kinde-convex-agent-tools';
import type {Governance} from './governance.js';

// --- Minimal MCP tool shape (typed locally; a genuine MCP tool handler that
// returns `{content, isError}` satisfies it). No @modelcontextprotocol import,
// so nothing framework-specific is pulled in. MCP tool args are flat JSON, which
// the gate models as ToolArgs. ---
export interface McpTextContent {
  type: 'text';
  text: string;
}
export interface McpToolResult {
  content: McpTextContent[];
  isError?: boolean;
}
export type McpToolHandler<TArgs extends ToolArgs = ToolArgs> = (
  args: TArgs
) => Promise<McpToolResult>;

function mcpError(payload: Record<string, unknown>): McpToolResult {
  return {
    content: [{type: 'text', text: JSON.stringify(payload)}],
    isError: true
  };
}

/**
 * Wrap an MCP tool handler so every call routes through the gate BEFORE
 * dispatch. Adds no policy of its own:
 * - allow → run the real handler.
 * - deny → a structured MCP error (403-style, `isError:true`) naming the reason.
 * - approve → a structured MCP error carrying the `approvalId`.
 * The decision is identical to calling `gate.checkTool` directly with the same
 * (subject, toolName, args).
 */
export function governMcpTool<TArgs extends ToolArgs>(
  gov: Governance & {toolName: string},
  handler: McpToolHandler<TArgs>
): McpToolHandler<TArgs> {
  return async (args) => {
    const decision = await gov.tools.gate.checkTool(gov.ctx, gov.subject, {
      tool: gov.toolName,
      args
    });
    if (decision.decision === 'deny') {
      return mcpError({
        error: 'tool_denied',
        reason: decision.reason,
        correlationId: decision.correlationId
      });
    }
    if (decision.decision === 'approve') {
      return mcpError({
        error: 'approval_pending',
        approvalId: decision.approvalId,
        correlationId: decision.correlationId
      });
    }
    return await handler(args);
  };
}
