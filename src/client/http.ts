import {httpActionGeneric} from 'convex/server';
import type {HttpRouter} from 'convex/server';
import {ConvexError} from 'convex/values';
import type {ComponentApi} from '../component/_generated/component.js';
import {fail, parseJson} from '../component/errors.js';
import type {ToolArgs} from '../component/validators.js';
import {billingCheckHandle} from './billing.js';
import type {BillingCheck} from './billing.js';

/**
 * What an app's {@link VerifyCaller} returns on success: at least the
 * authenticated `subject` the decision pipeline acts for. `org`/`agent` are
 * accepted for forward-compat (the identity model grows in later phases) but are
 * not yet consumed by the spine.
 */
export interface VerifiedCaller {
  subject: string;
  org?: string;
  agent?: string;
}

/**
 * Caller-authentication seam for the HTTP path. APP-SUPPLIED and REQUIRED to
 * mount the route: given the incoming `Request`, authenticate the caller and
 * return the {@link VerifiedCaller} (throw, or return a non-string subject, to
 * reject). This is the ONLY reason the route lives in client code — a component
 * HTTP action cannot read the app's `ctx.auth`/env, so authentication must
 * happen here, in the app's HTTP context, before the pipeline runs. The
 * component imports no auth package; auth is composed at the app level (the
 * blessed default is `@kinde-oss/kinde-convex-agent-auth`'s `verifyCaller`).
 */
export type VerifyCaller = (request: Request) => Promise<VerifiedCaller>;

/**
 * Options for {@link registerRoutes}. `verifyCaller` is REQUIRED — the HTTP seam
 * exists to authenticate a direct/cross-app caller, so it cannot be mounted
 * without one (there is no "open" tool-decision route). The seam ITSELF is
 * optional: an app that only calls in-Convex simply never calls registerRoutes.
 */
export interface RegisterRoutesOptions {
  /** Authenticate the caller and yield the subject. REQUIRED. */
  verifyCaller: VerifyCaller;
  /** Mount the route under this prefix. Default `/tools`. */
  pathPrefix?: string;
  /**
   * Optional billing seam, IDENTICAL to the client's `billingCheck`. When set,
   * an HTTP-originated call runs the SAME budget step as an in-Convex
   * `gate.checkTool` — so budget enforcement is uniform across entry points.
   * Absent → the budget step is skipped. It is only consulted AFTER
   * `verifyCaller` succeeds, so an unauthenticated request never reaches it.
   */
  billingCheck?: BillingCheck;
}

interface ToolRequest {
  tool: string;
  args?: ToolArgs;
  correlationId?: string;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {'Content-Type': 'application/json'}
  });
}

/** Extract a stable `{code, message}` from a typed ConvexError, else generic. */
function errorInfo(error: unknown): {code: string; message: string} {
  if (error instanceof ConvexError) {
    const data: unknown = error.data;
    if (
      typeof data === 'object' &&
      data !== null &&
      'code' in data &&
      'message' in data
    ) {
      const {code, message} = data as {code: unknown; message: unknown};
      if (typeof code === 'string' && typeof message === 'string') {
        return {code, message};
      }
    }
  }
  return {
    code: 'internal_error',
    message: 'The request could not be processed.'
  };
}

/** A single tool-argument value must be a JSON primitive or a string array. */
function isToolArgValue(value: unknown): boolean {
  if (value === null) {
    return true;
  }
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') {
    return true;
  }
  return Array.isArray(value) && value.every((x) => typeof x === 'string');
}

/**
 * Narrow an already-JSON-parsed body into a {@link ToolRequest}, or raise a typed
 * `tool_request_malformed` failure the route maps to 400. Validates the args
 * shape here so a bad body is a clean 400 rather than a deep validator throw.
 */
function parseToolRequest(value: unknown): ToolRequest {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail('tool_request_malformed', 'Expected a JSON object body.');
  }
  const {tool, args, correlationId} = value as Record<string, unknown>;
  if (typeof tool !== 'string' || tool.length === 0) {
    fail(
      'tool_request_malformed',
      'Field `tool` (a non-empty string) is required.'
    );
  }
  if (correlationId !== undefined && typeof correlationId !== 'string') {
    fail('tool_request_malformed', 'Field `correlationId` must be a string.');
  }
  let toolArgs: ToolArgs | undefined;
  if (args !== undefined) {
    if (typeof args !== 'object' || args === null || Array.isArray(args)) {
      fail('tool_request_malformed', 'Field `args` must be an object.');
    }
    for (const [key, val] of Object.entries(args as Record<string, unknown>)) {
      if (!isToolArgValue(val)) {
        fail(
          'tool_request_malformed',
          `Argument '${key}' has an unsupported value type.`
        );
      }
    }
    toolArgs = args as ToolArgs;
  }
  return {
    tool,
    ...(toolArgs === undefined ? {} : {args: toolArgs}),
    ...(correlationId === undefined ? {} : {correlationId})
  };
}

// Decision → HTTP status. The machine-readable decision is ALWAYS in the body;
// the status is a convenience for HTTP-native callers:
//   allow → 200, approve → 202 (accepted, pending human approval), deny → 403.
function statusForDecision(decision: 'allow' | 'deny' | 'approve'): number {
  if (decision === 'allow') {
    return 200;
  }
  if (decision === 'approve') {
    return 202;
  }
  return 403;
}

/**
 * Mount the tool-decision HTTP route onto the app's router (the Twilio pattern:
 * the handler is defined in CLIENT code and registered by the app, so it runs in
 * the app's HTTP context and can call the app-supplied {@link VerifyCaller} —
 * a component HTTP action could not). Call it from the app's `convex/http.ts`:
 *
 * ```ts
 * import {httpRouter} from 'convex/server';
 * import {registerRoutes} from '@kinde-oss/kinde-convex-agent-tools';
 * import {components} from './_generated/api.js';
 *
 * const http = httpRouter();
 * registerRoutes(http, components.tools, {verifyCaller: myVerifyCaller});
 * export default http;
 * ```
 *
 * Route: `POST ${pathPrefix}/check` (default `POST /tools/check`). Per request:
 *   1. Parse the JSON body (malformed → 400 `tool_request_malformed`).
 *   2. Authenticate via `verifyCaller` BEFORE the pipeline (throws/!subject →
 *      401 `caller_unauthenticated`; the decision pipeline never runs, so no
 *      grant lookup and no audit row for an unauthenticated request).
 *   3. Run `enforce.checkTool` with the verified subject and parsed tool/args —
 *      the SAME pipeline as an in-Convex `gate.checkTool`, INCLUDING the budget
 *      step when `billingCheck` is configured (so an HTTP-originated call is
 *      budget-gated identically). Return the decision as JSON with a mapped
 *      status (see {@link statusForDecision}). The subject is trusted only AFTER
 *      verifyCaller proves it — the in-Convex trust model is unchanged.
 */
export function registerRoutes(
  http: HttpRouter,
  component: ComponentApi,
  options: RegisterRoutesOptions
): void {
  const prefix = options.pathPrefix ?? '/tools';
  const verifyCaller = options.verifyCaller;

  http.route({
    path: `${prefix}/check`,
    method: 'POST',
    handler: httpActionGeneric(async (ctx, request) => {
      // 1. Parse + validate the body (boundary rule: typed error → 400).
      let toolRequest: ToolRequest;
      try {
        const rawText = await request.text();
        toolRequest = parseToolRequest(
          parseJson(rawText, 'tool_request_malformed', 'Expected a JSON body.')
        );
      } catch (error) {
        return json(400, errorInfo(error));
      }

      // 2. Authenticate the caller BEFORE the decision pipeline.
      let verified: VerifiedCaller;
      try {
        verified = await verifyCaller(request);
      } catch {
        return json(401, {
          code: 'caller_unauthenticated',
          message: 'The caller could not be authenticated.'
        });
      }
      if (
        typeof verified.subject !== 'string' ||
        verified.subject.length === 0
      ) {
        return json(401, {
          code: 'caller_unauthenticated',
          message: 'The caller could not be authenticated.'
        });
      }

      // 3. Run the decision pipeline with the VERIFIED subject — the SAME
      // pipeline (including the budget step) as an in-Convex gate.checkTool.
      // The billing handle is serialized only AFTER auth, and the billing
      // mutation itself runs inside checkTool, so no billing call precedes
      // authentication. Absent billingCheck → budget skipped, exactly as before.
      try {
        const billingCheck = await billingCheckHandle(options.billingCheck);
        const decision = await ctx.runMutation(component.enforce.checkTool, {
          subject: verified.subject,
          tool: toolRequest.tool,
          ...(toolRequest.args === undefined ? {} : {args: toolRequest.args}),
          ...(toolRequest.correlationId === undefined
            ? {}
            : {correlationId: toolRequest.correlationId}),
          ...(billingCheck === undefined ? {} : {billingCheck})
        });
        return json(statusForDecision(decision.decision), decision);
      } catch (error) {
        // A typed input/config error (e.g. contradictory_constraint) is a 400.
        return json(400, errorInfo(error));
      }
    })
  });
}
