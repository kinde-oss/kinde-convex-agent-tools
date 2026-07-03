<!-- Ideally, this should get auto-generated via tools like [auto-changelog](https://github.com/CookPete/auto-changelog). Eventually, this will get set up as part of the repository template. -->

## 0.1.0

Initial scaffold of the Kinde agent tools authorization Convex component (P0).

- **Component structure** — the official Convex component layout: `src/component/` (typed `convex.config.ts`, an empty schema, shared internal modules), `src/client/` (the class-based client shell), `src/test.ts` (the `register` harness helper), and a runnable `example/` reference app.
- **Client shell** — the `AgentTools` client carrying the `signingSecretEnvVar` config field and the optional, app-supplied `verifyCaller` (auth) and `billingCheck` (billing) composition seams, typed and accepted but not yet consulted.
- **Hardening baked in** — a typed `fail(code, message)` helper, a typed JSON-parse wrapper that maps a non-JSON body to a domain error, and validated enum-like environment variables (`MODE` defaults to `live`; an out-of-enum value is a hard failure).
- **Test harness** — `convex-test` + `vitest` wired up, with a smoke test that boots the component via `register()` and exercises the hardened helpers.
