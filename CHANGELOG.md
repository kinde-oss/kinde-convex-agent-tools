<!-- Ideally, this should get auto-generated via tools like [auto-changelog](https://github.com/CookPete/auto-changelog). Eventually, this will get set up as part of the repository template. -->

## 0.1.0

Initial release of the Kinde agent tools authorization Convex component.

- **Decision spine** — a single `checkTool` gate resolves every tool call in one transaction and returns a machine-readable `allow` / `deny` / `approve` decision, writing exactly one audit row per decision.
- **Allowlist** — deny-by-default grants: a call with no matching grant for the subject and tool is denied `no_grant` (`policy.grant`, `policy.revokeGrant`).
- **Argument policy** — per-argument constraints (`required`, `min`, `max`, `denyValue`, `allowValues`) evaluated against the call's args, denying `argument_denied` on a violation, with contradictory constraint sets rejected at grant time.
- **Approvals** — high-risk tools return `approve` and a pending approval that a human resolves; resolution is recorded and auditable, and an expired pending approval cannot be resolved (`policy.setToolRisk`, `approvals.approve`, `approvals.deny`, `approvals.getStatus`).
- **Reactive revocation** — a non-destructive kill-switch overlay with precedence global → org → agent → grant that denies `revoked` on the next call without deleting the grant (`revocations.revoke`, `revocations.liftRevocation`, `revocations.getStatus`).
- **Budget seam** — an optional `billingCheck` FunctionReference the spine invokes in-transaction with a redacted payload, denying `budget_exceeded` when not allowed; the component imports no billing package.
- **Execute wrapper** — `gate.runTool` decides then runs the tool, appending a completion audit row for an allowed execution.
- **Audit query** — one audit row per decision, read through a paginated, filterable, newest-first query that returns only the redacted argument digest, never raw args (`audit.query`).
- **App-mounted HTTP seam** — `registerRoutes` mounts `POST /tools/check` in the consuming app's `convex/http.ts`, gated by a required app-supplied `verifyCaller` that authenticates the caller before the pipeline runs.
- **Auth-agnostic subject seam** — every call takes a subject the app authenticates; the component never imports an auth package, so any auth can supply it.
- **Framework adapters** — thin, example-only MCP, Mastra, and LangChain wrappers that route a framework tool call through the gate without adding policy, keeping the core framework-free.
- **Example app** — a runnable reference app and an end-to-end integration test covering the full agent authorization narrative.
