import type {ToolArgs} from '@kinde-oss/kinde-convex-agent-tools';
import {gateOrThrow} from './governance.js';
import type {Governance} from './governance.js';

// --- Minimal LangChain tool shape (typed locally; a genuine
// DynamicStructuredTool with a `func`/`name` satisfies it). No langchain import.
// LangChain 1.x calls a tool's func with three positional args:
// (input, runManager, config): input arrives flat and schema-validated,
// runManager is the CallbackManagerForToolRun (undefined without callbacks,
// positionally present), config is the merged RunnableConfig. ---
export interface LangChainTool<TArgs extends ToolArgs, TRunManager, TConfig, TOutput> {
  name: string;
  func: (input: TArgs, runManager?: TRunManager, config?: TConfig) => Promise<TOutput>;
}

/**
 * Wrap a LangChain tool so its `func` is gated. Before the real func runs, the
 * call routes through the gate with the tool's flat input; on allow it runs with
 * the original (input, runManager, config) preserved, so LangChain's callback
 * manager and runnable config are never dropped; on deny/approve `gateOrThrow`
 * throws the typed error, which propagates through LangChain with its data intact.
 */
export function withKindeGovernance<TArgs extends ToolArgs, TRunManager, TConfig, TOutput>(
  tool: LangChainTool<TArgs, TRunManager, TConfig, TOutput>,
  gov: Governance
): LangChainTool<TArgs, TRunManager, TConfig, TOutput> {
  return {
    ...tool,
    func: async (input, runManager, config) => {
      await gateOrThrow(gov, tool.name, input);
      return await tool.func(input, runManager, config);
    }
  };
}
