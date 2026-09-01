import type {ToolArgs} from './validators.js';

/**
 * Canonical serialization of a call's arguments: keys sorted, then JSON — so the
 * same arguments always produce the same bytes regardless of key order, and two
 * DIFFERENT argument sets can never produce the same bytes. JSON.stringify does
 * the escaping, so a value containing separators (`,`, `:`, `"`) cannot forge
 * the encoding of a different argument set.
 *
 * Unlike `redactArgs`, this hashes the RAW values — it is never stored or
 * displayed, only hashed (see {@link argBindingDigest}).
 */
function canonicalize(args: ToolArgs): string {
  return JSON.stringify(
    Object.keys(args)
      .sort()
      .map((key) => [key, args[key]])
  );
}

const encoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * THE ARGUMENT-BINDING DIGEST — the single shared helper for both minting an
 * approval's binding and comparing it at `checkTool`. Both sides MUST call this
 * function (never re-derive the hash) so a mint and a compare can never drift.
 *
 * SHA-256 over the {@link canonicalize} bytes, hex-encoded. This is a SECURITY
 * boundary, not a display value: an approved approval is a single-use ticket
 * bound to this digest, so an attacker who could find two argument sets sharing
 * a digest could get an approval minted for harmless args and spend it on
 * dangerous ones. That is why this is SHA-256 and not the non-cryptographic
 * FNV-1a used by `redactArgs` — finding a collision here must be infeasible.
 *
 * Distinct from `redactArgs` on purpose. `redactArgs` produces the REDACTED
 * digest that is stored and read (audit/`toolCalls`/approval display); this one
 * is never rendered, so it can hash raw values without leaking them: a preimage
 * of a SHA-256 digest is not recoverable, and the digest is only ever compared
 * against another digest of args the caller already supplied.
 */
export async function argBindingDigest(args: ToolArgs): Promise<string> {
  const buffer = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(canonicalize(args))
  );
  return `v1:sha256:${toHex(new Uint8Array(buffer))}`;
}
