# Example app — agent governance, end to end

This runnable Convex app composes the **real** `kinde-convex-agent-tools` component the way a host app would. Only the two app-level seams are fakes:

- **verifyCaller** (`convex/http.ts`) — verifies a Kinde token's signature against the tenant JWKS with `jose` and returns its `sub` as the subject (in production, prefer `@kinde-oss/kinde-convex-agent-auth`'s `verifyCaller`, which also checks the audience, the agent registry and revocation). It authenticates the caller of `POST /tools/check`. The subject is **derived from the verified token**, never from a header — the grant lookup is identity-agnostic, so the subject _is_ the trust decision.
- **billingCheck** (`convex/fakeBilling.ts`) — an app mutation standing in for a billing spend check (in production, pair with `@kinde-oss/kinde-convex-agent-billing`).

Neither sibling package is a dependency — the example **composes**, it does not import them.

## The narrative

`convex/e2e.test.ts` drives one agent (`agent_007`) through every layer via the public client surface (`convex/example.ts`), and reads the audit trail back as one coherent story keyed by correlation ids:

1. **Grant + allow** — grant `search`; then a decision arrives via the verifyCaller-composed **HTTP route** (subject from the verified token's `sub`) and an in-Convex **`gate.runTool`** actually runs the tool → `granted` → `executed`.
2. **Out of allowlist** — an ungranted tool → `deny no_grant`; the tool never runs.
3. **Argument policy** — `transfer` with a `max` cap: over-cap → `deny argument_denied`, within cap → `allow` (the policy discriminates, it does not blanket-deny).
4. **High-risk approval** — a `high`-risk tool → `approve` (approvalId); a human `approves`; the app then executes → `approval_required` → `approval_approved` → `executed`.
5. **Reactive revocation** — revoke the (subject, tool) grant → the same call now `deny revoked` though it allowed moments earlier (grant untouched); lift → `allow` again.

The budget step is real (the allow/approve paths record a `billingCalls` row); the component makes every decision — the test mocks nothing about it.

## The wrappers in `convex/example.ts` are deliberately insecure

`convex/http.ts` shows the real pattern (derive the subject from a verified token). **`convex/example.ts` does not** — do not copy it into production. Its wrappers take `subject` and `approver` as plain client-supplied arguments so each function's intent stays readable in one screen:

- `grantTool` / `grantToolWithMaxArg` are **admin, authority-widening** functions exposed as public mutations — any caller can grant themselves any tool, or pick their own `max` cap.
- `checkGovernedTool` takes `subject` from client input, so a caller can be decided against anyone's allowlist.
- `approveApproval` takes `approver` from client input, so an agent can approve its own high-risk call and sign it as anyone.

Each carries an `EXAMPLE ONLY — INSECURE AS WRITTEN` comment naming the fix. For the real patterns, see the root README's [Security model](../README.md#security-model) and [Composing with agent-auth](../README.md#composing-with-agent-auth).

Run it with `npm test` from the repo root.
