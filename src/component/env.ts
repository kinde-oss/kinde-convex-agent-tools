import {fail} from './errors.js';

/** Operating mode. `test` relaxes external calls for local development. */
export type Mode = 'test' | 'live';

const MODES: readonly Mode[] = ['test', 'live'];

function isMode(value: string): value is Mode {
  return (MODES as readonly string[]).includes(value);
}

/** The component's validated environment. */
export interface ToolsEnv {
  /** The validated operating mode; defaults to `live`. */
  mode: Mode;
}

/**
 * Read and validate the component's environment. Enum-like vars are validated
 * here rather than trusted: `MODE` defaults sensibly to `live`, and any value
 * outside the enum is a hard failure instead of a silent fallback.
 *
 * The component holds NO SECRET. Grants, tool policies and approvals are
 * admin-set policy rows that live inside the database trust boundary, so their
 * integrity comes from the app-layer auth that gates who may write them — not
 * from a signature the component would have to verify against itself. (Contrast
 * agent-auth, which signs DELEGATIONS: those are bearer artifacts that travel
 * outside the database and must prove they were not tampered with in transit.)
 * The one place argument integrity is load-bearing — an approval ticket bound to
 * its arguments — is enforced by the SHA-256 binding in `digest.ts`, which needs
 * no secret because it authenticates nothing; it only has to be collision-proof.
 */
export function readEnv(): ToolsEnv {
  let mode: Mode = 'live';
  const rawMode = process.env.MODE;
  if (rawMode !== undefined && rawMode.length > 0) {
    if (!isMode(rawMode)) {
      fail(
        'invalid_env',
        `MODE must be one of ${MODES.join(', ')}; got "${rawMode}".`
      );
    }
    mode = rawMode;
  }

  return {mode};
}
