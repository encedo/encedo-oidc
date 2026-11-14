/**
 * HEM key attestation (firmware 1.3, POST /api/system/config/attestation).
 *
 * Flow:
 *  1. /enrollment/validate issues { nonce, aud } next to the challenge and keeps
 *     both in the enrollment session.
 *  2. The page asks the HEM for an attestation JWT of the new key with a
 *     signature proof of possession: hem.attest(token, { nonce, aud, kid, popArgs: {} }),
 *     and on a PPA also the device certificate (getAttestation().crt).
 *  3. /enrollment/submit hands { attestation, crt } to verifyKeyAttestation():
 *       - Attest.verify (offline): device signature by the header jwk, iss, aud,
 *         nonce, kid, and the PoP over (aud, pubkey, nonce) by the key itself;
 *       - the attested key is the key being enrolled (pubkey.primary) and was
 *         generated inside the HEM (privatekey, not derived / imported);
 *       - assurance 'hard' (PPA, secure element): the device certificate chains
 *         to the pinned Encedo root, then attest.encedo.com/v1/validate
 *         (registry, revocation);
 *       - assurance 'soft' (EPA): the token alone for now - attest.encedo.com
 *         does not validate EPA yet.
 *
 * Result status:
 *   verified    hard, the device chains to the Encedo root (and online did not say invalid)
 *   token_only  the token, PoP and key binding hold, the device origin is not proven
 *               (EPA, or a PPA whose chain could not be checked)
 *   failed      a check failed - see `reason`
 *   absent      no attestation was sent
 *
 * Policy (ATTEST_POLICY, overridable per user with user.attest_policy):
 *   advisory      record the result, never refuse (default)
 *   require       refuse unless verified or token_only
 *   require_hard  refuse unless verified (hard, chained)
 */

import { Attest, ENCEDO_ROOT_SHA256 } from '../../hem-sdk-js/hem-sdk.js';
import { randomBytes } from 'crypto';
import { oidcIssuer, issuer } from './issuer.js';

export const ATTEST_POLICIES = ['advisory', 'require', 'require_hard'];

// attest.encedo.com: CA list for the chain and the online verdict. Empty = offline
// only (no chain can be built then, so a PPA ends as token_only).
const ATTEST_URL  = (process.env.ATTEST_URL ?? 'https://attest.encedo.com').trim();
// The pinned root. Overridable for the test PKI only; production keeps the SDK pin.
const ROOT_SHA256 = (process.env.ATTEST_ROOT_SHA256 || ENCEDO_ROOT_SHA256).toLowerCase();

// One instance: it fetches the CA list once and keeps it.
const attestClient = ATTEST_URL ? new Attest(ATTEST_URL) : null;

/** Policy in force for a user: their override, else the server default. */
export function attestPolicy(userPolicy) {
  if (ATTEST_POLICIES.includes(userPolicy)) return userPolicy;
  const env = (process.env.ATTEST_POLICY ?? '').trim();
  return ATTEST_POLICIES.includes(env) ? env : 'advisory';
}

/** Does `policy` refuse an enrollment with this result? */
export function attestRefuses(policy, result) {
  if (policy === 'require')      return !['verified', 'token_only'].includes(result.status);
  if (policy === 'require_hard') return result.status !== 'verified';
  return false;
}

/** The verifier id sent to the HEM: 1..64 printable ASCII. */
export function attestAudience() {
  const iss = oidcIssuer() || issuer().replace(/\/+$/, '');
  if (iss.length <= 64) return iss;
  try { return new URL(iss).host.slice(0, 64); } catch { return iss.slice(0, 64); }
}

/** A fresh challenge for the enrollment session. */
export function newAttestChallenge() {
  return { nonce: randomBytes(32).toString('base64'), aud: attestAudience() };
}

/**
 * @param {object} a
 * @param {string|null} a.attestation  the JWT from hem.attest()
 * @param {string|null} a.crt          base64 DER device certificate (PPA)
 * @param {{nonce: string, aud: string}|null} a.challenge  from the session
 * @param {string} a.kid               32 hex, the key being enrolled
 * @param {string} a.pubkeyHex         its public key as the HEM gives it
 *                                     (EC compressed, Ed25519 raw), hex
 */
export async function verifyKeyAttestation({ attestation, crt, challenge, kid, pubkeyHex }) {
  const out = { status: 'absent', assurance: null, reason: null, online: null, jwt: null, crt: null };
  if (!attestation) { out.reason = 'no_attestation'; return out; }
  if (typeof attestation !== 'string' || attestation.length > 16384) return fail(out, 'malformed');
  out.jwt = attestation;
  if (!challenge?.nonce || !challenge?.aud) return fail(out, 'no_challenge');

  const state = { aud: challenge.aud, nonce: new Uint8Array(Buffer.from(challenge.nonce, 'base64')), kid: kid.toLowerCase(), pop: 'sig' };
  let r;
  try { r = await Attest.verify(attestation, state); }
  catch (e) { return fail(out, `verify_error:${e.message}`); }
  out.assurance = r.claims?.device?.assurance ?? null;
  if (!r.ok) return fail(out, r.failed.join(','));

  // The attested key must be the key that goes into the JWKS ...
  const key = r.claims.key;
  const attestedPub = Buffer.from(String(key?.pubkey?.primary ?? ''), 'base64').toString('hex');
  if (attestedPub !== pubkeyHex.toLowerCase()) return fail(out, 'pubkey_mismatch');
  // ... and generated inside the HEM, not imported or derived from a secret.
  if (key.properties?.privatekey !== true || key.properties?.derived !== false) return fail(out, 'key_not_generated_in_hem');

  if (out.assurance === 'soft') {
    // EPA: attest.encedo.com does not validate EPA devices yet - the token is all we have.
    out.status = 'token_only';
    out.reason = 'soft_assurance';
    return out;
  }
  if (out.assurance !== 'hard') return fail(out, `assurance:${out.assurance}`);

  // PPA: the device key must chain to the pinned Encedo root. Certificate dates are NOT
  // checked on purpose: the PPA certificate's ~2-year validity is the manufacturer's
  // warranty, not the attestation's -- chained and not revoked = genuine device.
  if (typeof crt !== 'string' || !crt || crt.length > 8192) {
    out.status = 'token_only'; out.reason = 'no_crt'; return out;
  }
  out.crt = crt;
  if (!attestClient) { out.status = 'token_only'; out.reason = 'offline_no_ca'; return out; }
  let chain;
  try { chain = await withTimeout(attestClient.verifyDevice(r.point, crt, { rootSha256: ROOT_SHA256 })); }
  catch (e) {
    console.warn('[Attestation] CA list unavailable:', e.message);
    out.status = 'token_only'; out.reason = 'ca_unavailable'; return out;
  }
  if (!chain.ok) return fail(out, `chain:${chain.reason}`);

  // Registry and revocation. A network failure leaves the offline verdict.
  try {
    const v = await withTimeout(attestClient.validate(attestation, { crt }));
    out.online = v?.status ?? 'unknown';
    if (out.online === 'invalid') return fail(out, 'online_invalid');
  } catch (e) {
    console.warn('[Attestation] attest.encedo.com unreachable:', e.message);
    out.online = 'error';
  }
  out.status = 'verified';
  return out;
}

// The SDK sets no timeout in Node, and this runs under the 30 s enrollment lock.
function withTimeout(p, ms = 10_000) {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`timeout after ${ms} ms`)), ms); })])
    .finally(() => clearTimeout(t));
}

function fail(out, reason) {
  out.status = 'failed';
  out.reason = reason;
  return out;
}

/**
 * The stored public key in the form the HEM attests it: Ed25519 raw 32 B as
 * stored; EC stored as uncompressed X||Y, attested as the compressed point.
 * Decided by length, so a record from before key_type existed works too.
 */
export function hemPubkeyHex(stored) {
  const hex = String(stored ?? '').toLowerCase();
  if (hex.length === 64) return hex;                               // Ed25519
  const b = Buffer.from(hex, 'hex');
  if (![64, 96, 132].includes(b.length)) return null;              // P-256 / P-384 / P-521
  const x = b.subarray(0, b.length / 2), y = b.subarray(b.length / 2);
  return ((y[y.length - 1] & 1) ? '03' : '02') + x.toString('hex');
}
