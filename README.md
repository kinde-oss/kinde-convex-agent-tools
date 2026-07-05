# Kinde Convex Agent Tools

The Kinde agent tools authorization component for [Convex](https://convex.dev) — tool-call authorization for AI agents: deny-by-default grants, per-argument policy, human approval for high-risk tools, reactive revocation, an optional budget seam, and an audit row for every decision.

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Development

This package is a Convex component plus a thin client. Day-to-day development:

- `npm install`: install the dependencies.
- `npm run build:codegen`: regenerate the component code and build it.
- `npm test`: run the full `convex-test` + `vitest` suite (with type-checking).
- `npm run typecheck`: type-check the package and the example app.
- `npm run lint`: run ESLint.
- `npm run format`: run Prettier over the repo.

The `example/` directory is a runnable reference app that installs the component via `app.use` and exercises every layer end to end; `example/convex/example.ts` shows the intended usage of each function and `example/convex/e2e.test.ts` tells the full story as one test.

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

This component gives a Convex app a complete authorization story for autonomous and supervised agents: it decides every tool call through a single `checkTool` gate against a deny-by-default allowlist, enforces per-argument policy, routes high-risk tools to human approval, applies a reactive revocation kill switch, optionally consults a billing seam for budget, and writes exactly one audit row per decision — all in a single Convex transaction. Every decision takes plain inputs (a `subject`, a `tool`, and its `args`); the authentication of the caller and the billing budget are separate, app-composed concerns (see the seams below).

### Install and wire up

Install the package:

```bash
npm i @kinde-oss/kinde-convex-agent-tools
```

Add the component to your app's `convex/convex.config.ts` and pass through its environment:

```ts
import {defineApp} from 'convex/server';
import {v} from 'convex/values';
import agentTools from '@kinde-oss/kinde-convex-agent-tools/convex.config.js';

const app = defineApp({
  env: {
    TOOLS_SIGNING_SECRET: v.string()
  }
});

app.use(agentTools, {
  env: {
    TOOLS_SIGNING_SECRET: app.env.TOOLS_SIGNING_SECRET
  }
});

export default app;
```

The component reads these environment variables:

| Variable | Required | Purpose |
| --- | --- | --- |
| `TOOLS_SIGNING_SECRET` | yes | Secret used to HMAC-sign tool-call authorizations. |
| `MODE` | no | `test` relaxes external calls for local development; defaults to `live`. |

Set them with `npx convex env set`:

```bash
npx convex env set TOOLS_SIGNING_SECRET a-long-random-secret
```

Construct the client once:

```ts
// convex/agentTools.ts
import {AgentTools} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';

export const agentTools = new AgentTools(components.tools);
```

Grant a tool to a subject, then decide (or decide and execute) a call:

```ts
await agentTools.policy.grant(ctx, subject, {tool: 'search'});

const decision = await agentTools.gate.checkTool(ctx, subject, {
  tool: 'search',
  args: {query: 'kinde'}
});
// decision: {decision: 'allow' | 'deny' | 'approve', reason?, approvalId?, correlationId}

// Or decide and run the tool in one call, from an action:
const {result, correlationId} = await agentTools.gate.runTool(
  ctx,
  subject,
  {tool: 'search', args: {query: 'kinde'}},
  async () => runSearch()
);
```

`gate.runTool` must be called from an action: on a deny or approve it throws, and a throw inside a single mutation would roll back the decision's audit row, whereas in an action its internal `checkTool` commits independently first.

### The HTTP route

Mount the tool-decision route in your `convex/http.ts` (it runs in your app's context, where it can authenticate the caller):

```ts
import {httpRouter} from 'convex/server';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';

const http = httpRouter();

registerRoutes(http, components.tools, {
  verifyCaller: async (request) => {
    // Authenticate the caller and return the subject the decision acts for.
    const subject = await authenticate(request);
    return {subject};
  }
});

export default http;
```

This mounts `POST /tools/check`. `verifyCaller` is required to mount the route — a request that fails it is rejected 401 before the decision pipeline runs. The route returns 200 for allow, 202 for approve, and 403 for deny; HTTP callers should read the response body's `decision`/`reason`, not only the status, since different deny reasons (`no_grant`, `budget_exceeded`) share 403. When configured with a `billingCheck`, an HTTP-originated call runs the identical budget step as an in-Convex `gate.checkTool`, so budget enforcement is uniform across entry points; without one, the budget step is skipped. See `RegisterRoutesOptions` for `pathPrefix` and `billingCheck`.

### The `verifyCaller` seam

`verifyCaller` is the app-supplied authentication seam for the HTTP route. It authenticates the incoming request and returns the subject; it throws (or returns a non-string subject) to reject.

```ts
type VerifyCaller = (request: Request) => Promise<VerifiedCaller>;

interface VerifiedCaller {
  subject: string; // the authenticated principal the decision acts for
  org?: string; // optional tenant, forward-compat
  agent?: string; // optional agent id, forward-compat
}
```

The component never imports an auth package and never reads `ctx.auth`; any auth can supply the subject. In-Convex callers pass the subject directly to `gate.checkTool`/`gate.runTool`; the HTTP route derives it from `verifyCaller`.

### The `billingCheck` seam

`billingCheck` is the optional app-supplied budget seam. It is a `FunctionReference` to an app mutation that the spine invokes in the same transaction during the budget step, passing a redacted payload and receiving a decision:

```ts
// payload → result
{subject: string; tool: string; argDigest: string; correlationId: string}
{allow: boolean; reason?: string}
```

Wire it when constructing the client; a not-allowed result denies with reason `budget_exceeded`:

```ts
export const agentTools = new AgentTools(components.tools, {
  billingCheck: internal.billing.check
});
```

The payload carries only the redacted `argDigest`, never raw args. A `budget_exceeded` deny commits — the billing mutation's metering write and the deny audit row both persist; only a malformed billing return rolls the transaction back. The component imports no billing package.

### Capabilities

| Layer | What it does |
| --- | --- |
| Allowlist | Deny-by-default grants: a call with no matching grant is denied `no_grant` (`policy.grant`, `policy.revokeGrant`). |
| Argument policy | Per-argument constraints — `required`, `min`, `max`, `denyValue`, `allowValues` — evaluated against the call's args, denying `argument_denied` on a violation (set via `policy.grant`). |
| Approvals | High-risk tools return `approve` and require human resolution before running (`policy.setToolRisk`, `approvals.approve`, `approvals.deny`, `approvals.getStatus`). |
| Revocation | A reactive kill-switch overlay, precedence global → org → agent → grant, that denies `revoked` without deleting the grant (`revocations.revoke`, `revocations.liftRevocation`, `grantRevocationKey`). |
| Budget | An optional billing seam consulted in-transaction, denying `budget_exceeded` when not allowed (`billingCheck`). |
| Decide & execute | `gate.checkTool` returns a machine-readable decision; `gate.runTool` decides then runs the tool and writes a completion audit row (call from an action). |
| Audit | Exactly one audit row per decision, read through a paginated, filterable, newest-first query (`audit.query`). |

### Composes with auth & billing

`@kinde-oss/kinde-convex-agent-tools`, [`@kinde-oss/kinde-convex-agent-auth`](https://github.com/kinde-oss/kinde-convex-agent-auth), and [`@kinde-oss/kinde-convex-agent-billing`](https://github.com/kinde-oss/kinde-convex-agent-billing) are siblings in the Kinde AgentKit. They pair at the app level: auth resolves who the caller is through the `verifyCaller` seam, and billing meters the budget through the `billingCheck` seam. This component imports neither, so you can adopt it with or without them.

### Framework adapters

The decision API is framework-neutral: `gate.checkTool` and `gate.runTool` take plain inputs (a `subject`, a `tool` name, and its `args`), never a framework's tool or request object. The component imports no agent framework, so it governs tool calls from any framework — or none.

Bridging a specific framework is the job of a thin, optional adapter (~15 lines) that translates that framework's tool-call shape into a plain gate call and translates the decision back into what the framework expects (a throw, an error result, whatever its tool contract is). Adapters live in `example/adapters/`, never in the component. The repo ships reference adapters for MCP, Mastra, and LangChain as worked examples — they are illustrations of the pattern, not a fixed list of supported frameworks. To govern a framework not shown, write the same small translator against its tool-execute signature and point it at the same `gate.checkTool`.

## Documentation

For details, see the [Kinde docs](https://kinde.com/docs/), the [developer tools](https://kinde.com/docs/developer-tools/) section, and the [Convex components docs](https://docs.convex.dev/components).

## Publishing

The Kinde core team handles publishing.

## Contributing

Please refer to Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
