import type {ToolArgs} from '@kinde-oss/kinde-convex-agent-tools';

import {gateOrThrow} from './governance.js';

import type {Governance} from './governance.js';

// --- Minimal Mastra tool shape (typed locally; a genuine Mastra tool created

// with `createTool({ id, execute })` satisfies it). No @mastra/core import.

// Mastra 1.x calls execute(args, options): the tool's input arrives FLAT as the

// first positional arg (not under `.context`), and Mastra's runtime context

// (agent, requestContext, toolCallId, messages) is the second. ---

export interface MastraTool<TArgs extends ToolArgs, TOptions, TOutput> {
  id: string;

  execute: (args: TArgs, options?: TOptions) => Promise<TOutput>;
}

/**

 * Wrap a Mastra tool so its `execute` is gated. Before the real execute runs,

 * the call routes through the gate with the tool's FLAT args; on allow it runs

 * with the original (args, options) preserved, so Mastra's runtime context is

 * never dropped; on deny/approve `gateOrThrow` throws the typed error.

 */

export function withKindeGovernance<TArgs extends ToolArgs, TOptions, TOutput>(
  tool: MastraTool<TArgs, TOptions, TOutput>,

  gov: Governance
): MastraTool<TArgs, TOptions, TOutput> {
  return {
    ...tool,

    execute: async (args, options) => {
      await gateOrThrow(gov, tool.id, args);

      return await tool.execute(args, options);
    }
  };
}
