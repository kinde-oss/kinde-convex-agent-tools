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

Every decision acts for a `subject` — the identity the tool call is attributed to. The recommended way to supply it is Kinde: authenticate the caller with [`@kinde-oss/kinde-convex-agent-auth`](https://github.com/kinde-oss/kinde-convex-agent-auth) (or, for HTTP callers, a `verifyCaller` that validates a Kinde token) and pass the resolved subject in. The component itself is identity-agnostic and imports no Kinde SDK, so any auth can supply the subject and it runs standalone — but Kinde is the paved path, and pairs with the billing sibling for budget enforcement.

### Security model

Read this before exposing any of this component to the network. Its functions are raw machinery with **no authentication of their own** — the host app is the security boundary. This component decides whether an agent may act, so an unwrapped function is not an information leak — it is an authorization bypass.

1. **Component mutations are not authenticated.** A Convex component cannot see the host app's auth context (`ctx.auth`), so every mutation and query here is callable by whatever surface the host app exposes. Nothing in the component checks _who_ is calling; that is the app's job. Treat each function as machinery to wrap, not an endpoint to expose.

2. **Admin-only functions — never expose these publicly.** Wrap each in an app-layer function that authenticates a human or admin first. Everything that writes policy is admin-only, but the ones that **widen** authority are the sharp ones:

   | Function | Why it is admin-only |
   | --- | --- |
   | `policy.grant` | **Widens.** Creates the allowlist row that turns a `no_grant` deny into an allow. Also carries `argumentConstraints` and `risk`, so it sets how narrow the grant is. |
   | `policy.revokeGrant` | Deletes a grant. Attenuating, but a caller who can delete grants can disable any agent. |
   | `policy.setToolRisk` | **Widens.** Lowering a tool from `high` to `medium`/`low` removes the human-approval requirement for that tool deployment-wide. |
   | `policy.setToolPolicy` | **Widens.** Relaxing or clearing (`null`) a tool's global `argumentConstraints` removes limits that apply regardless of grant. |
   | `approvals.approve` | **Widens.** Mints the single-use ticket that lets a high-risk call through. See point 4. |
   | `approvals.deny` | Resolves an approval terminally — a caller who can deny can also grief every pending request. |
   | `revocations.revoke` | The kill switch. Attenuating, but `targetType: 'global'` denies **every** tool call in the deployment; an open surface here is a deployment-wide DoS. |
   | `revocations.liftRevocation` | **Widens.** Lifts the kill switch — the one function that can undo an emergency revocation. |
   | `audit.query` | Deployment-wide read. **Every filter is optional**, so an unfiltered call returns every subject's decision history. Bind the filter to the caller's verified identity; a caller-supplied `subject` filter scopes nothing, because a caller who omits it gets everything. |

   Note `policy.revoke` does not exist — grant deletion is `policy.revokeGrant` (the kill-switch overlay is `revocations.revoke`, a different thing: it denies reactively without deleting the grant).

   `audit.recordCompletion` is deliberately not on this list. It appends the `executed` row and is called by `gate.runTool` on the normal path, so it cannot be admin-gated — instead it **validates**: it refuses to write unless this component already recorded an `allow` decision for the same `correlationId`, `subject` and `tool`, failing closed with `no_matching_decision`. A caller cannot fabricate execution history with it, only replay a completion that already happened (an idempotent no-op).

3. **Agent-facing endpoints must NEVER accept a client-supplied `subject`.** Derive it from an authenticated identity — agent-auth's `verifyCaller`/`authorize` — and pass **the verified value** into `gate.checkTool`. The grant lookup is deliberately identity-agnostic: the component asks only "does a grant exist for this subject and tool?" and never checks that the caller _is_ that subject, because it has no way to. **The `subject` IS the trust decision.** Take it from a request body or a header and every grant in the deployment belongs to whoever asks for it — an agent claims `subject: 'user_admin'` and inherits the admin's allowlist. See [Composing with agent-auth](#composing-with-agent-auth) for the wiring.

4. **`approvals.approve` / `approvals.deny` take `approver` as a trusted string.** The component stores it verbatim as the record of who authorized a high-risk call; it cannot tell a real approver from an attacker-chosen string. This is the same class of trusted input as the elevation approver in agent-auth, whose `POST /agent/elevation/respond` route fails closed with a **501** unless the app mounts an `authorizeApprover` hook that extracts the approver from a verified token. Hold this component's approval path to that same standard: supply `approver` from a **verified human session** (e.g. a Kinde user access token), never from the request body — the body is attacker-controlled and must never be read for approver identity. An agent must not be able to approve its own high-risk call.

5. **Always go through `AgentTools.gate`; never expose raw `enforce.checkTool`.** The client's `gate.checkTool` strips a smuggled `billingCheck` out of its per-call options, so the budget seam can only come from the `AgentTools` constructor. That guard lives in the **client**, not the component: a caller who reaches `components.tools.enforce.checkTool` directly can pass their own `billingCheck` `FunctionHandle` and choose which mutation adjudicates their budget — pointing it at an allow-everything function turns budget enforcement off for that call. The component cannot defend itself here (a `FunctionHandle` is just a string it invokes), so the rule is structural: agent-facing code calls `gate.checkTool`, and `enforce.checkTool` is never wrapped in an app function that forwards caller input.

6. **Production checklist:**
   - [ ] No agent-facing surface takes `subject` from client input — every one derives it from `verifyCaller`/`authorize` (point 3).
   - [ ] Every function in the point-2 table is behind an authenticated admin/human wrapper.
   - [ ] `approver` comes from a verified human session, never a request body or header (point 4).
   - [ ] Agent code calls `AgentTools.gate.checkTool`, never `components.tools.enforce.checkTool` (point 5).
   - [ ] `audit.query` wrappers bind their filters to the caller's verified identity rather than forwarding client filters.
   - [ ] `registerRoutes` is mounted with a `verifyCaller` that verifies a **token signature**, not a header (the route cannot be mounted without one, but a `verifyCaller` that trusts `X-Subject` satisfies the type and defeats the point).
   - [ ] Org- and agent-level revocations from agent-auth are **not** relied on to stop tool calls — they do not apply until P7 (see [P7 roadmap](#p7-roadmap)).

### Install and wire up

Install the package:

```bash
npm i @kinde-oss/kinde-convex-agent-tools
```

Add the component to your app's `convex/convex.config.ts`:

```ts
import {defineApp} from 'convex/server';
import agentTools from '@kinde-oss/kinde-convex-agent-tools/convex.config.js';

const app = defineApp();

app.use(agentTools);

export default app;
```

The component requires no secret, so there is nothing to thread through. It reads one optional environment variable:

| Variable | Required | Purpose |
| --- | --- | --- |
| `MODE` | no | `test` relaxes external calls for local development; defaults to `live`. |

Set it with `npx convex env set`:

```bash
npx convex env set MODE live
```

**Why no signing secret?** Grants, tool policies and approvals are admin-set policy rows that live inside the database trust boundary — their integrity comes from the app-layer auth that gates who may write them (see [Security model](#security-model)), not from a signature the component would verify against itself. This is the same line agent-auth draws between its `tenantPolicies` (unsigned DB rows) and its delegations (signed, because they are bearer artifacts that travel outside the database). The one place argument integrity is load-bearing — an approval bound to the exact arguments it authorizes — is enforced by a SHA-256 digest, which needs no secret because it authenticates nothing; it only has to be collision-proof.

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
import {createRemoteJWKSet, jwtVerify} from 'jose';
import {registerRoutes} from '@kinde-oss/kinde-convex-agent-tools';
import {components} from './_generated/api.js';

const http = httpRouter();
const jwks = createRemoteJWKSet(
  new URL(`https://${process.env.KINDE_DOMAIN}/.well-known/jwks`)
);

registerRoutes(http, components.tools, {
  verifyCaller: async (request) => {
    // VERIFY a bearer token, then DERIVE the subject from it. The subject must
    // come from something you checked — never from a header or the body.
    const token = (request.headers.get('Authorization') ?? '').replace(
      /^Bearer /,
      ''
    );
    const {payload} = await jwtVerify(token, jwks, {
      issuer: `https://${process.env.KINDE_DOMAIN}`
    });
    if (typeof payload.sub !== 'string') {
      throw new Error('no sub claim'); // a throw is a 401
    }
    return {subject: payload.sub};
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
  org?: string; // accepted, NOT consumed — see below
  agent?: string; // accepted, NOT consumed — see below
}
```

**`subject` is the only field that reaches the decision.** `org` and `agent` are accepted for forward compatibility and dropped: `registerRoutes` passes only `subject` to `checkTool`, so supplying them changes no decision today. Do not read their presence as tenant isolation or agent scoping — until P7, org/agent-level revocation does not apply and agent-scoped grants are never matched (see [P7 roadmap](#p7-roadmap)).

It must **derive** the subject from something it verified — a token signature, a session — never read it from a header or body. The route cannot be mounted without a `verifyCaller`, but a `verifyCaller` that returns `request.headers.get('X-Subject')` satisfies the type while defeating the point: the grant lookup is identity-agnostic, so the subject _is_ the trust decision (see [Security model](#security-model), point 3). `example/convex/http.ts` shows the pattern with a Kinde token verified against the tenant JWKS.

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

This component is built to run as part of the Kinde AgentKit, and that pairing is the recommended way to deploy it: [`@kinde-oss/kinde-convex-agent-auth`](https://github.com/kinde-oss/kinde-convex-agent-auth) resolves who the caller is through the `verifyCaller` seam, and [`@kinde-oss/kinde-convex-agent-billing`](https://github.com/kinde-oss/kinde-convex-agent-billing) meters the budget through the `billingCheck` seam. Together the three siblings give an agent a complete identity → authorization → budget story at the app level. This component imports neither, so it runs with or without them — but the AgentKit stack is the paved road.

For the budget seam in the other direction — how billing adapts its `principalType`/`principalId`/`unit` shape to this component's `BillingCheckPayload` — see billing's [Composing with agent-tools](https://github.com/kinde-oss/kinde-convex-agent-billing#composing-with-agent-tools). The short version of the sharpest edge there: **the seam is check-only.** `billingCheck` asks "may they spend?" and this component never reports what was consumed, so metering is entirely the app's job after the tool runs.

### Composing with agent-auth

[`@kinde-oss/kinde-convex-agent-auth`](https://github.com/kinde-oss/kinde-convex-agent-auth) answers _who is calling_; this component answers _whether that identity may invoke this tool with these arguments_. They pair at the app level through the `subject`, and neither imports the other.

**This component trusts its caller completely.** It has no way to check a token, so whoever calls it must be the code that verified one. The grant lookup asks only "does a grant exist for this subject and tool?" — it never checks that the caller _is_ that subject. That makes the wiring rule simple, and it is the whole integration: verify first, then gate on the identity the verification returned.

#### The canonical mapping: `subject` is `caller.subject`

`verifyCaller` returns a `VerifiedAgent`. Map its `subject` — the token's verified `sub` claim (falling back to `azp` for M2M clients) — onto this component's `subject`:

| agent-auth `VerifiedAgent` | Use for a tool grant? |
| --- | --- |
| `subject: string` | **Yes — this is the canonical mapping.** Always present, and it is the acting identity every grant, approval and audit row is keyed by. |
| `agentId: string \| null` | No. It is the _registry_ id of the agent (null when the token's `azp` maps to no registered agent), not the acting identity. Agent-scoped grants are [P7](#p7-roadmap) — `toolGrants.agent` exists but nothing queries it. |
| `orgCode: string \| null` | Not yet. The spine takes no org; org-level revocation does not apply until [P7](#p7-roadmap). |
| `scopes: string[]` | No — a separate layer. See below. |

Note this differs from billing on purpose: billing bills `caller.agentId ?? caller.subject` because it meters _who pays_, which is the registered agent when there is one. Tool grants key on _who is acting_, which is always `caller.subject`.

```ts
// convex/agentToolCalls.ts
import {action} from './_generated/server.js';
import {components} from './_generated/api.js';
import {v} from 'convex/values';
import {AgentAuth} from '@kinde-oss/kinde-convex-agent-auth';
import {AgentTools, toolArgsValidator} from '@kinde-oss/kinde-convex-agent-tools';

const agentAuth = new AgentAuth(components.agentAuth);
const agentTools = new AgentTools(components.tools);

/**
 * The canonical agent-facing tool endpoint: verify, then gate. Note what the
 * args do NOT contain — no subject. The caller says what it wants to do; it
 * never says who it is.
 */
export const callTool = action({
  args: {
    token: v.string(),
    tool: v.string(),
    args: v.optional(toolArgsValidator)
  },
  handler: async (ctx, args) => {
    // 1. Verify the caller's Kinde token. Throws on an invalid, expired, or
    //    unregistered token, so nothing below runs for an unverified caller.
    const caller = await agentAuth.verifyCaller(ctx, args.token);

    // 2. Gate the call on the VERIFIED subject — never on anything from `args`.
    //    runTool decides and, on allow, runs the tool and writes the completion
    //    row. On deny/approve it throws and the tool never runs.
    return await agentTools.gate.runTool(
      ctx,
      caller.subject,
      {tool: args.tool, ...(args.args === undefined ? {} : {args: args.args})},
      async () => await runTheTool(args.tool, args.args)
    );
  }
});
```

The order matters as much as the pieces. Verification must happen before the gate call, in the same function, with the verified value flowing directly into it. Verifying a token and then gating a subject taken from `args` is the confused-deputy bug with extra steps.

If the endpoint also has to answer "may this agent do this _class_ of action at all?", use agent-auth's `authorize` instead of `verifyCaller` — it verifies the token **and** decides the action against an instance in one call, returning `{caller, decision}`. Its `caller` is the same `VerifiedAgent`, so it feeds `gate.checkTool` identically.

#### Scopes and tool grants are separate layers — both run

An agent-auth **scope** and a tool **grant** answer different questions, and passing one implies nothing about the other:

- A **scope** says what class of action the agent's _token_ permits (`payments:write`). It is carried by the token, minted by Kinde, and attenuated by delegations.
- A **tool grant** says whether _this subject_ may invoke _this tool_ with _these arguments_ (`wire_transfer`, `amount ≤ 100`). It is a policy row in this component's database, and it is deny-by-default.

An agent holding `payments:write` is still denied `no_grant` for `wire_transfer` unless a grant exists; an agent with a `wire_transfer` grant is still stopped by `authorize` if its token lacks the scope. Run both — they compose as an intersection, and each can only narrow the other. Neither is a substitute: scopes have no notion of the arguments a call carries, and grants have no notion of what the token was minted to permit.

#### Tool approval vs agent-auth elevation

Both put a human in the loop, and they are not interchangeable:

| | agent-auth **elevation** | agent-tools **approval** |
| --- | --- | --- |
| What it raises | The agent's authority level for a **scope**, on one instance | Authorization for **one specific invocation** |
| Bound to | The approved scopes, for the instance's lifetime/expiry | The exact `argBinding` — one call, one set of arguments |
| Lifetime | Reusable while the elevation is unexpired | **Single-use.** Consumed on the next matching call; the next call must be approved afresh |
| Triggered by | The agent hitting a scope wall (`elevation.request`) | The tool's effective risk being `high` |

Use **elevation** when the agent needs a capability it structurally lacks ("this agent may now touch payments at all"). Use **tool approval** when the agent already has the capability but this particular call is dangerous ("yes, wire _this_ $9,000 _now_"). A useful test: if approving it twice for different arguments would be equally fine, it is elevation; if the arguments are the reason a human is being asked, it is a tool approval.

The argument binding is why they cannot be swapped. An approval is minted against `argBinding`, a SHA-256 digest of the exact arguments, so an approval for `{amount: 500}` never authorizes `{amount: 999}` — the ticket simply does not match and the call routes to a fresh approval. (This is distinct from the `argDigest` on audit rows, which is the *redacted* digest kept for display; the binding is what the spine actually compares.) Elevation has no equivalent, because a scope has no arguments to bind to.

### P7 roadmap

The identity model here stops at the `subject`. These are the known gaps — each is **accepted for forward compatibility, not wired**, and the code carries a comment at every site:

- **Agent-scoped grants.** `toolGrants.agent` and its `by_agent` index exist, but every grant is written with `agent: null` and the spine looks up by `by_subject` only. An agent-scoped grant would never match today.
- **`org` in the spine.** `checkTool` takes no org argument; `VerifiedCaller.org` and `VerifiedAgent.orgCode` are accepted at the HTTP seam and dropped. There is no tenant isolation in the decision — grants are global to the deployment.
- **Org/agent revocation propagation.** The revocation overlay structurally supports `global`, `org`, `agent` and `grant` levels, but the spine passes `null` for org and agent, so **only `global` and `grant` revocations can fire.** Revoking an org or an agent in agent-auth does **not** deny tool calls here yet. Do not rely on it as a kill switch across components — revoke at the `grant` level (via `grantRevocationKey`) or `global` until P7 lands.

Not on this list: signed grant binding. Grants and approvals are admin-set policy rows inside the database trust boundary, so they are not signed by design (see [Install and wire up](#install-and-wire-up)), and the one place argument integrity gates a decision — an approval's single-use ticket — is already bound by a SHA-256 digest.

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
