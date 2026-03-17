/**
 * Input validators — centralised, reusable.
 * Each function returns null (valid) or a string (error message).
 */

// ─── Primitives ────────────────────────────────────────────────

/** Non-empty string, optional max length. */
export function vRequired(value, label, maxLen = 256) {
  if (typeof value !== 'string' || !value.trim()) return `${label} is required`;
  if (value.length > maxLen) return `${label} exceeds max length (${maxLen})`;
  return null;
}

/** Optional string — only validates if present. */
export function vOptional(value, label, maxLen = 256) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') return `${label} must be a string`;
  if (value.length > maxLen) return `${label} exceeds max length (${maxLen})`;
  return null;
}

// ─── Domain validators ─────────────────────────────────────────

/**
 * RFC 5322 — simplified but catches obvious garbage.
 * Full RFC 5322 is overkill; this covers 99.9% of real addresses.
 */
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,24}$/;
export function vEmail(value, label = 'email') {
  const base = vRequired(value, label, 320);
  if (base) return base;
  if (!EMAIL_RE.test(value.trim())) return `${label} is not a valid email address`;
  return null;
}

/**
 * HTTP/HTTPS URL validator.
 * @param {boolean} httpsOnly      — if true, rejects plain http (except localhost)
 * @param {boolean} allowLocalhost — allow localhost / 127.0.0.1
 * Note: private IP ranges (RFC1918) are intentionally allowed — HSM devices (PPA) are
 * typically on a local network (e.g. 192.168.7.1 / my.ence.do). Use httpsOnly to enforce TLS.
 */
export function vUrl(value, label = 'url', { httpsOnly = false, allowLocalhost = true } = {}) {
  const base = vRequired(value, label, 2048);
  if (base) return base;
  let u;
  try { u = new URL(value.trim()); } catch { return `${label} is not a valid URL`; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return `${label} must use http or https`;
  }
  if (httpsOnly && u.protocol !== 'https:') {
    if (!(allowLocalhost && (u.hostname === 'localhost' || u.hostname === '127.0.0.1'))) {
      return `${label} must use https (http allowed only for localhost)`;
    }
  }
  if (u.username || u.password) return `${label} must not contain credentials`;
  return null;
}

/** Username: alphanumeric + limited special chars, 2–64 chars. */
const USERNAME_RE = /^[a-zA-Z0-9._@-]{2,64}$/;
export function vUsername(value, label = 'username') {
  const base = vRequired(value, label, 64);
  if (base) return base;
  if (!USERNAME_RE.test(value.trim())) {
    return `${label} may only contain letters, digits, '.', '_', '@', '-' (2–64 chars)`;
  }
  return null;
}

/** Display name: printable chars, 0–128. */
export function vDisplayName(value, label = 'name') {
  return vOptional(value, label, 128);
}

/**
 * PKCE code_challenge — RFC 7636 §4.2:
 *   BASE64URL(SHA-256(ASCII(code_verifier))) = 43 base64url chars.
 */
const CHALLENGE_RE = /^[A-Za-z0-9\-._~]{43}$/;
export function vCodeChallenge(value, label = 'code_challenge') {
  if (!value) return null; // optional — enforced per-client upstream
  if (typeof value !== 'string') return `${label} must be a string`;
  if (!CHALLENGE_RE.test(value)) return `${label} must be 43 base64url characters (S256)`;
  return null;
}

/**
 * PKCE code_verifier — RFC 7636 §4.1: 43–128 unreserved chars.
 */
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
export function vCodeVerifier(value, label = 'code_verifier') {
  if (!value) return null;
  if (typeof value !== 'string') return `${label} must be a string`;
  if (!VERIFIER_RE.test(value)) {
    return `${label} must be 43–128 unreserved characters (RFC 7636)`;
  }
  return null;
}

/** state: opaque, max 512 chars (generous for nested JSON states). */
export function vState(value, label = 'state') {
  return vOptional(value, label, 512);
}

/** nonce: opaque, max 256 chars. */
export function vNonce(value, label = 'nonce') {
  return vOptional(value, label, 256);
}

/** Ed25519 signature in base64url: 64 bytes → ~86 base64url chars. */
const SIG_RE = /^[A-Za-z0-9\-_]{86}={0,2}$/;
export function vSignature(value, label = 'signature') {
  const base = vRequired(value, label, 90);
  if (base) return base;
  if (!SIG_RE.test(value)) return `${label} is not a valid base64url Ed25519 signature`;
  return null;
}

/** Token TTL in seconds: 60 – 86400 (1 min – 24 h). */
export function vTtl(value, label, { min = 60, max = 86400 } = {}) {
  const n = parseInt(value, 10);
  if (isNaN(n) || n < min || n > max) {
    return `${label} must be an integer between ${min} and ${max} seconds`;
  }
  return null;
}

/** UUID v4 format. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function vUuid(value, label = 'id') {
  if (typeof value !== 'string' || !UUID_RE.test(value)) {
    return `${label} must be a valid UUID`;
  }
  return null;
}

// ─── Batch helper ──────────────────────────────────────────────

/**
 * Run multiple validators; returns first error or null.
 * Usage: const err = validate(vEmail(email), vUrl(hsm_url), vUsername(username));
 */
export function validate(...results) {
  return results.find(r => r !== null) ?? null;
}
