import type {ToolArgs} from '@kinde-oss/kinde-convex-agent-tools';
import {gateOrThrow} from './governance.js';
import type {Governance} from './governance.js';

// --- Minimal Mastra tool shape (typed locally; a genuine Mastra tool created
// with `createTool({ id, execute })` satisfies it). No @mastra/core import.
// Mastra passes the input under `context`; tool args are flat, modeled as
// ToolArgs. ---
export interface MastraToolExecutionContext<TArgs extends ToolArgs> {
  context: TArgs;
}
export interface MastraTool<TArgs extends ToolArgs, TOutput> {
  id: string;
  description?: string;
  execute: (execCtx: MastraToolExecutionContext<TArgs>) => Promise<TOutput>;
}

/**
 * Wrap a Mastra tool so its `execute` is gated. Before the real execute runs,
 * the gate is consulted with (subject, tool.id, args); allow → run; deny/approve
 * → throw the typed error per Mastra's tool contract (`tool_denied` /
 * `approval_pending`, see {@link gateOrThrow}). Adds no policy — same decision as
 * the raw gate.
 */
export function withKindeGovernance<TArgs extends ToolArgs, TOutput>(
  tool: MastraTool<TArgs, TOutput>,
  gov: Governance
): MastraTool<TArgs, TOutput> {
  return {
    ...tool,
    execute: async (execCtx) => {
      await gateOrThrow(gov, tool.id, execCtx.context);
      return await tool.execute(execCtx);
    }
  };
}
