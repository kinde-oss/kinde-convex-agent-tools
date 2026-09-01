import {ConvexError} from 'convex/values';

/**
 * Throw a machine-readable error. `code` is a stable identifier callers can
 * branch on via `ConvexError.data.code`; `message` is for humans. Every failure
 * path in this component funnels through here so errors stay typed end to end
 * (no raw `Error`, no leaking a stack across the function boundary).
 */
export function fail(code: string, message: string): never {
  throw new ConvexError({code, message});
}

/**
 * Parse a JSON string, mapping a non-JSON body to a typed {@link fail} instead
 * of a raw `SyntaxError`. Every external/untrusted JSON body (a tool-args blob,
 * a webhook payload, an upstream API response) is parsed through here so a
 * malformed body becomes a domain error the caller can branch on rather than an
 * opaque throw. `code`/`message` let each call site attribute the failure to
 * its own domain.
 */
export function parseJson<T = unknown>(
  text: string,
  code: string = 'invalid_json',
  message: string = 'Expected a valid JSON body.'
): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    fail(code, message);
  }
}
