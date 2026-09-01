import {ConvexError} from 'convex/values';
import type {
  AgentTools,
  GateResult,
  RunMutationCtx,
  ToolArgs
} from '@kinde-oss/kinde-convex-agent-tools';

/**
 * What every adapter threads from the app: the tools client, a Convex run
 * context, and the APP-AUTHENTICATED subject. Adapters NEVER invent identity —
 * they pass the app's subject straight into the plain gate call.
 */
export interface Governance {
  tools: AgentTools;
  ctx: RunMutationCtx;
  subject: string;
}

/**
 * Run the gate for one tool call and, for the "throw on non-allow" adapters
 * (Mastra / LangChain), raise a typed error that mirrors `gate.runTool`:
 * deny → `tool_denied` (with the DenyCode reason), approve → `approval_pending`
 * (with the approvalId). On allow it returns the decision so the caller runs the
 * real tool. This adds NO policy — it only calls the gate and translates.
 */
export async function gateOrThrow(
  gov: Governance,
  toolName: string,
  args: ToolArgs
): Promise<GateResult> {
  const decision = await gov.tools.gate.checkTool(gov.ctx, gov.subject, {
    tool: toolName,
    args
  });
  if (decision.decision === 'deny') {
    throw new ConvexError({
      code: 'tool_denied',
      message: `Tool '${toolName}' was denied.`,
      reason: decision.reason ?? null,
      correlationId: decision.correlationId
    });
  }
  if (decision.decision === 'approve') {
    throw new ConvexError({
      code: 'approval_pending',
      message: `Tool '${toolName}' requires human approval before it can run.`,
      approvalId: decision.approvalId ?? null,
      correlationId: decision.correlationId
    });
  }
  return decision;
}
