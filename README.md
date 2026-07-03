# Kinde Convex Agent Tools

The Kinde agent tools authorization component for [Convex](https://convex.dev) — the in-app tool-call authorization layer for AI agents, backed by Kinde.

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Development

This package is a Convex component plus a thin client. Day-to-day development:

- `npm install`: install the dependencies.
- `npm run build:codegen`: regenerate the component code and build it.
- `npm test`: run the full `convex-test` + `vitest` suite (with type-checking).
- `npm run typecheck`: type-check the package and the example app.
- `npm run lint`: run ESLint.
- `npm run format`: run Prettier over the repo.

The `example/` directory is a runnable reference app that installs the component via `app.use` and will exercise every layer end to end as the component grows.

### Initial set up

1. Clone the repository to your machine:

   ```bash
   git clone https://github.com/kinde-oss/kinde-convex-agent-tools.git
   ```

2. Go into the project:

   ```bash
   cd kinde-convex-agent-tools
   ```

3. Install the dependencies:

   ```bash
   npm install
   ```

4. Regenerate the component code and build:

   ```bash
   npm run build:codegen
   ```

5. Run the tests:

   ```bash
   npm test
   ```

## Usage

This component is the in-app tool-call authorization layer for AI agents on Convex. When an agent goes to use a tool, the call passes through the component, which decides **allow** / **deny** / **require-human-approval**, enforces a deny-by-default allowlist, meters the call, and writes exactly one audit row. Its wedge is location: it runs _inside_ the Convex app, in the same transaction as your data.

The core is framework-agnostic — it exposes a decision API taking plain inputs (`subject`, `tool`, `args`), never framework objects. It composes with authentication via a subject plus an optional `verifyCaller` slot, and with billing via an optional `billingCheck` slot, and imports neither. Thin optional adapters (MCP/Mastra/LangChain) live in `example/` or optional sub-exports, never in core.

> **Honest limitation.** This is an in-app decision API the developer calls or wraps a tool with — **not** a network proxy.

> **Status.** `0.1.0` is the P0 scaffold: the component structure, the client shell with the `verifyCaller`/`billingCheck` composition seams, and the test harness. The decision API, allowlist, metering, approval gate, and audit log land in subsequent phases. The subsections below are placeholders filled in as those phases ship.

### Install and wire up

_Placeholder — the full install and wiring walkthrough lands alongside the decision API._

Install the package:

```bash
npm i @kinde-oss/kinde-convex-agent-tools
```

Add the component to your app's `convex/convex.config.ts` and wire its environment:

```ts
import {defineApp} from 'convex/server';
import {v} from 'convex/values';
import tools from '@kinde-oss/kinde-convex-agent-tools/convex.config.js';

const app = defineApp({
  env: {
    TOOLS_SIGNING_SECRET: v.string()
  }
});

app.use(tools, {
  env: {
    TOOLS_SIGNING_SECRET: app.env.TOOLS_SIGNING_SECRET
  }
});

export default app;
```

Set the signing secret out-of-band (never hardcode it):

```bash
npx convex env set TOOLS_SIGNING_SECRET "$(openssl rand -base64 32)"
```

Construct the client from your app's generated `components`:

```ts
import {AgentTools} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';

export const agentTools = new AgentTools(components.tools);
```

### Composition seams

_Placeholder._ The client accepts two optional, app-supplied seams so the component stays independent of any specific auth or billing package:

- `verifyCaller` — authenticate a direct/cross-app caller of an app-mounted HTTP route.
- `billingCheck` — decide whether billing permits a tool call.

## Documentation

For details on integrating this component into your project, head over to the [Kinde docs](https://kinde.com/docs/) and see the [developer tools](https://kinde.com/docs/developer-tools/) section.

## Publishing

The core team handles publishing.

_Placeholder — the release/publish steps (GitHub Actions) are documented here as they are set up._

## Contributing

Please refer to Kinde's [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
