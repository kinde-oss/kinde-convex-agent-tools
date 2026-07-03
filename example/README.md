# Example app — agent governance, end to end

This runnable Convex app composes the **real** `kinde-convex-agent-tools` component the way a host app would. Only the two app-level seams are fakes:

- **verifyCaller** (`convex/http.ts`) — a shared-secret header check standing in for auth (in production, pair with `@kinde-oss/kinde-convex-agent-auth`). It authenticates the caller of `POST /tools/check` and yields the subject.
- **billingCheck** (`convex/fakeBilling.ts`) — an app mutation standing in for a billing spend check (in production, pair with `@kinde-oss/kinde-convex-agent-billing`).

Neither sibling package is a dependency — the example **composes**, it does not import them.

## The narrative

`convex/e2e.test.ts` drives one agent (`agent_007`) through every layer via the public client surface (`convex/example.ts`), and reads the audit trail back as one coherent story keyed by correlation ids:

1. **Grant + allow** — grant `search`; then a decision arrives via the verifyCaller-composed **HTTP route** (subject from the header) and an in-Convex **`gate.runTool`** actually runs the tool → `granted` → `executed`.
2. **Out of allowlist** — an ungranted tool → `deny no_grant`; the tool never runs.
3. **Argument policy** — `transfer` with a `max` cap: over-cap → `deny argument_denied`, within cap → `allow` (the policy discriminates, it does not blanket-deny).
4. **High-risk approval** — a `high`-risk tool → `approve` (approvalId); a human `approves`; the app then executes → `approval_required` → `approval_approved` → `executed`.
5. **Reactive revocation** — revoke the (subject, tool) grant → the same call now `deny revoked` though it allowed moments earlier (grant untouched); lift → `allow` again.

The budget step is real (the allow/approve paths record a `billingCalls` row); the component makes every decision — the test mocks nothing about it.

Run it with `npm test` from the repo root.
