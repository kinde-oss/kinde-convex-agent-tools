import {createFunctionHandle} from 'convex/server';
import type {FunctionReference} from 'convex/server';
import type {
  BillingCheckPayload,
  BillingCheckResult
} from '../component/validators.js';

/**
 * Billing seam (P5). App-supplied: a FunctionReference to a MUTATION that
 * decides whether billing permits a tool call. It receives a
 * {@link BillingCheckPayload} (only the REDACTED digest — never raw args) and
 * returns a {@link BillingCheckResult}. The spine INVOKES it IN THE SAME
 * TRANSACTION via a FunctionHandle — the core imports NO billing package. A
 * mutation reference (not a query) mirrors billing's own spend-authority check,
 * so composing across the suite is uniform.
 */
export type BillingCheck = FunctionReference<
  'mutation',
  'public' | 'internal',
  BillingCheckPayload,
  BillingCheckResult
>;

/**
 * Serialize an optional `billingCheck` reference into the `billingCheck`
 * FunctionHandle string that `enforce.checkTool` accepts, or `undefined` when
 * none is configured (budget step skipped). Must run in a Convex function
 * context (mutation/action/HTTP action), where `createFunctionHandle` is
 * available. Shared by every entry point — the in-Convex client (`gate`) and
 * the HTTP route — so their budget threading can never diverge.
 */
export async function billingCheckHandle(
  billingCheck: BillingCheck | undefined
): Promise<string | undefined> {
  return billingCheck === undefined
    ? undefined
    : await createFunctionHandle(billingCheck);
}
