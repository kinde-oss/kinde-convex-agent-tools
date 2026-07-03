import type {ToolArgs} from '@kinde-oss/kinde-convex-agent-tools';
import {gateOrThrow} from './governance.js';
import type {Governance} from './governance.js';

// --- Minimal LangChain structured-tool shape (typed locally; a genuine
// DynamicStructuredTool with a `func`/`name` satisfies it). No langchain import.
// Tool args are the structured input, flat, modeled as ToolArgs. ---
export interface LangChainTool<TArgs extends ToolArgs, TOutput> {
  name: string;
  description?: string;
  func: (input: TArgs) => Promise<TOutput>;
}

/**
 * Wrap a LangChain tool so its `func` is gated. Before the real func runs, the
 * gate is consulted with (subject, tool.name, input); allow → run; deny/approve
 * → throw the typed error per LangChain's tool contract (`tool_denied` /
 * `approval_pending`, see {@link gateOrThrow}). Adds no policy — same decision as
 * the raw gate.
 */
export function withKindeGovernance<TArgs extends ToolArgs, TOutput>(
  tool: LangChainTool<TArgs, TOutput>,
  gov: Governance
): LangChainTool<TArgs, TOutput> {
  return {
    ...tool,
    func: async (input) => {
      await gateOrThrow(gov, tool.name, input);
      return await tool.func(input);
    }
  };
}
