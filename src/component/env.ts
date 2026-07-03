import {fail} from './errors.js';

/** The env var that holds the HMAC signing secret, unless the app overrides it. */
export const DEFAULT_SIGNING_SECRET_ENV_VAR = 'TOOLS_SIGNING_SECRET';

/** Operating mode. `test` relaxes external calls for local development. */
export type Mode = 'test' | 'live';

const MODES: readonly Mode[] = ['test', 'live'];

function isMode(value: string): value is Mode {
  return (MODES as readonly string[]).includes(value);
}

/** The component's validated environment. */
export interface ToolsEnv {
  /** The HMAC signing secret (non-empty). */
  signingSecret: string;
  /** The validated operating mode; defaults to `live`. */
  mode: Mode;
}

/**
 * Read and validate the component's environment. Enum-like vars are validated
 * here rather than trusted: `MODE` defaults sensibly to `live`, and any value
 * outside the enum is a hard failure instead of a silent fallback. The signing
 * secret is required and must be non-empty. `signingSecretEnvVar` names the var
 * to read it from (default {@link DEFAULT_SIGNING_SECRET_ENV_VAR}), so an app
 * that mounts the component under a different secret var can point at it.
 */
export function readEnv(
  signingSecretEnvVar: string = DEFAULT_SIGNING_SECRET_ENV_VAR
): ToolsEnv {
  const signingSecret = process.env[signingSecretEnvVar];
  if (signingSecret === undefined || signingSecret.length === 0) {
    fail(
      'missing_env',
      `Required environment variable ${signingSecretEnvVar} is not set.`
    );
  }

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

  return {signingSecret, mode};
}
