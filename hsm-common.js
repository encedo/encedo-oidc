/**
 * hsm-common.js -- helpers shared by signin.js, enrollment.js and signup.js.
 *
 * Pure functions only: no DOM, no SDK import (hemErrMsg duck-types HemError by
 * its `code`), so the module is also loadable in Node for unit tests
 * (test/hsm-common.test.js). Served at /hsm-common.js -- a new UI file lives in
 * THREE places (src/app.js route, Dockerfile COPY, release.yml zip list).
 */

// --- Key type maps --------------------------------------------------------------

/** key_type -> HSM createKeyPair type string. */
export function hsmKeyType(keyType) {
  if (keyType === 'P256') return 'SECP256R1';
  if (keyType === 'P384') return 'SECP384R1';
  if (keyType === 'P521') return 'SECP521R1';
  return 'ED25519';
}

/** key_type -> exdsaSign alg string for the Encedo HSM API. */
export function exdsaAlg(keyType) {
  if (keyType === 'P256') return 'SHA256WithECDSA';
  if (keyType === 'P384') return 'SHA384WithECDSA';
  if (keyType === 'P521') return 'SHA512WithECDSA';
  return 'Ed25519';
}

/** Human-readable label (enrollment / signup forms). */
export function keyTypeLabel(keyType) {
  if (keyType === 'P256') return 'P-256 (ECDSA)';
  if (keyType === 'P384') return 'P-384 (ECDSA)';
  if (keyType === 'P521') return 'P-521 (ECDSA)';
  return 'Ed25519 (EdDSA)';
}

/** Human-readable JWS algorithm label (sign-in screens). */
export function keyTypeDisplay(keyType) {
  if (keyType === 'P256') return 'ES256 / P-256';
  if (keyType === 'P384') return 'ES384 / P-384';
  if (keyType === 'P521') return 'ES512 / P-521';
  return 'EdDSA / Ed25519';
}

// --- Signature encoding ---------------------------------------------------------

/**
 * DER-encoded ECDSA signature -> IEEE P1363 (r || s, fixed width), which is what
 * JWS (RFC 7518 s.3.4) and the backend's `dsaEncoding: 'ieee-p1363'` expect.
 * Handles the short-form and long-form SEQUENCE length (P-521 signatures are
 * > 127 bytes). Malformed input throws instead of producing garbage that the
 * server would reject with a misleading "signature verification failed".
 */
export function derToP1363(derBytes, keyType) {
  const n = { P256: 32, P384: 48, P521: 66 }[keyType];
  if (!n) throw new Error(`derToP1363: unsupported key type ${keyType}`);
  if (!(derBytes instanceof Uint8Array) || derBytes.length < 8 || derBytes[0] !== 0x30) {
    throw new Error('derToP1363: not a DER SEQUENCE');
  }
  let pos = 1;
  if (derBytes[pos] & 0x80) {
    const lenBytes = derBytes[pos] & 0x7f;
    if (lenBytes < 1 || lenBytes > 2) throw new Error('derToP1363: bad SEQUENCE length');
    pos += 1 + lenBytes;
  } else {
    pos += 1;
  }
  function readInt() {
    if (derBytes[pos++] !== 0x02) throw new Error('derToP1363: expected INTEGER');
    const len = derBytes[pos++];
    if (len === undefined || len & 0x80 || pos + len > derBytes.length) throw new Error('derToP1363: bad INTEGER length');
    let val = derBytes.subarray(pos, pos + len);
    pos += len;
    while (val.length > 1 && val[0] === 0) val = val.subarray(1);   // strip sign padding
    if (val.length > n) throw new Error('derToP1363: INTEGER longer than the curve order');
    const out = new Uint8Array(n);
    out.set(val, n - val.length);                                    // right-align
    return out;
  }
  const r = readInt(), s = readInt();
  const out = new Uint8Array(n * 2);
  out.set(r, 0); out.set(s, n);
  return out;
}

export function bytesToBase64url(bytes) {
  let b = '';
  for (const byte of bytes) b += String.fromCharCode(byte);
  return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Standard base64 (what the HSM returns for a public key) -> bytes. */
export function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// --- JWT ------------------------------------------------------------------------

/**
 * Decode one base64url JWT part as UTF-8 JSON. `atob` alone yields latin1, so a
 * name like "Łukasz Żółć" in the payload came out as mojibake on the confirm
 * screen -- decode the bytes properly.
 */
function decodeJwtPart(part) {
  const b64   = part.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

export function decodeJwtHeader(jwtOrSigningInput) {
  try { return decodeJwtPart(jwtOrSigningInput.split('.')[0]); } catch { return null; }
}

export function decodeJwtPayload(jwtOrSigningInput) {
  try { return decodeJwtPart(jwtOrSigningInput.split('.')[1]); } catch { return null; }
}

// --- HTTP -----------------------------------------------------------------------

/**
 * fetch + JSON with one error shape. A proxy's 502/504 page is HTML, so
 * res.json() used to throw "SyntaxError: Unexpected token '<'" straight into
 * the UI; now any non-2xx becomes an Error carrying the server's
 * error_description (or error code), the HTTP status and the parsed body.
 */
export async function fetchJson(url, opts = {}) {
  const res  = await fetch(url, opts);
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = null; } }
  if (!res.ok) {
    const e = new Error(data?.error_description || data?.error || `Server error (HTTP ${res.status})`);
    e.status = res.status;
    e.code   = data?.error ?? null;
    e.data   = data;
    throw e;
  }
  return data;
}

// --- HEM errors -----------------------------------------------------------------

/** One message per failure class, for every page. Duck-types HemError. */
export function hemErrMsg(err) {
  const code = err?.code;
  if (typeof code === 'string') {
    if (code === 'http_401')  return 'Authentication failed. Is the passphrase correct?';
    if (code === 'http_403')  return 'The HSM refused this operation (not permitted for this key or scope).';
    if (code === 'denied')    return 'The request was declined on your mobile device.';
    if (code === 'timeout')   return 'No answer from your mobile device in time. Try again or use the passphrase.';
    if (code === 'aborted')   return 'Cancelled.';
    if (code === 'network')   return 'Cannot reach the HSM. Check the URL and that the device is online.';
    if (code === 'checkin_error' || code === 'broker_error') return `HSM check-in failed (${code}): ${err.message}`;
    if (code.startsWith('http_')) return `HSM error (${code}): ${err.message}`;
    if (err?.status !== undefined) return `HSM error (${code}): ${err.message}`;
  }
  return `Error: ${err?.message || 'Unknown error'}`;
}

/**
 * Authorize a scope with the passphrase when there is one, otherwise by mobile
 * push. `signal` lets the page cancel the push.
 */
export function authorizeScope(hem, password, scope, { signal = null, onPending = null } = {}) {
  return password
    ? hem.authorizePassword(password, scope)
    : hem.authorizeRemote(scope, { pollInterval: 2_000, pollTimeout: 60_000, signal, onPending });
}
