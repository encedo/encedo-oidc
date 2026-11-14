/**
 * Levels of assurance of a sign-in (HEM FW 1.3, DEV-511 login context).
 *
 * At every sign-in the page asks the HEM for an attestation over a server
 * challenge with the token it signs with (hem.attest(useToken, {nonce, aud,
 * kid})). The device adds the `auth` block: how that token was obtained
 * (passphrase or the paired phone app), how long ago, from which Origin, and
 * what the app declared (actx). The server checks it offline - no call to
 * attest.encedo.com per sign-in - against the device that was attested at
 * enrollment (the device key in user.attest_jwt).
 *
 *   L0  the HEM signature only (no or unusable attestation)
 *   L1  the login context comes from the enrolled device (any method)
 *   L2  L1 + the user verified: passphrase, or the phone app locked with a PIN
 *       / biometrics, or this Allow confirmed with them (actx.uvm) + the login
 *       came from this OP's origin
 *   L3  L2 + the device is a PPA proven genuine at enrollment (attest_status
 *       verified, hard) + by phone: this Allow confirmed with PIN / biometrics
 *       (uvm bio|pin) and the app's storage key in hardware (hw sb|tee|se)
 *
 * The phone app's `actx` is signed by the app and copied by the device, not
 * interpreted by it; `hw` says where the key that wraps the app's storage
 * lives (the pairing key itself is decrypted into app memory to sign).
 *
 * Required level = max(client.min_loa, user.min_loa, the lowest level the RP
 * named in acr_values). acr is emitted as urn:encedo:loa:<n>.
 */

export const LOA_MAX = 3;
const LOA_PREFIX = 'urn:encedo:loa:';
export const loaUrn = (n) => `${LOA_PREFIX}${n}`;
export const LOA_VALUES = [0, 1, 2, 3].map(loaUrn);

const HW_HARDWARE = ['sb', 'tee', 'se'];
const UV_PROMPT   = ['bio', 'pin'];
const LOCK_UV     = ['pin', 'bio+pin'];

/** '' / undefined / garbage -> 0; '0'..'3' -> number. */
export function parseLoa(v) {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isInteger(n) && n >= 0 && n <= LOA_MAX ? n : 0;
}

/** True for a value an admin may store: 0..3 (number or digit string). */
export function validLoa(v) {
  return (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= LOA_MAX)
      || (typeof v === 'string' && /^[0-3]$/.test(v));
}

/** The lowest level among the acr_values this OP knows; null when none. */
export function acrValuesLevel(acrValues) {
  const levels = String(acrValues ?? '').split(' ').filter(Boolean)
    .filter(v => v.startsWith(LOA_PREFIX))
    .map(v => v.slice(LOA_PREFIX.length))
    .filter(v => /^[0-3]$/.test(v))
    .map(Number);
  return levels.length ? Math.min(...levels) : null;
}

export function requiredLevel(clientRaw, userRaw, acrValues) {
  return Math.max(parseLoa(clientRaw?.min_loa), parseLoa(userRaw?.min_loa), acrValuesLevel(acrValues) ?? 0);
}

/**
 * What a verified login context is worth.
 * @param {object} a
 * @param {object|null} a.auth      r.auth from Attest.verify, null when unusable
 * @param {boolean} a.deviceMatch   the attesting device is the enrolled one
 * @param {boolean} a.orgMatch      auth.org is this OP's origin
 * @param {boolean} a.hardDevice    the enrolled device is a PPA verified at enrollment
 * @returns {{level: number, amr: string[], uv: boolean}}
 */
export function assessLogin({ auth, deviceMatch, orgMatch, hardDevice }) {
  const amr = ['hwk'];
  if (!auth || !deviceMatch) return { level: 0, amr, uv: false };

  const actx = auth.actx && typeof auth.actx === 'object' ? auth.actx : {};
  const uvm  = typeof actx.uvm === 'string' ? actx.uvm : null;
  let uv = false, perApproval = false;
  if (auth.method === 'pwd') {
    amr.push('pwd');
    uv = true; perApproval = true;           // the passphrase is typed for this login
  } else {
    amr.push('user');                        // approved on the paired phone
    if (UV_PROMPT.includes(uvm)) { uv = true; perApproval = true; }
    else if (LOCK_UV.includes(actx.lock)) uv = true;
  }
  if (uv) amr.push('mfa');

  let level = 1;
  if (uv && orgMatch) level = 2;
  if (level === 2 && hardDevice && perApproval) {
    if (auth.method === 'pwd' || HW_HARDWARE.includes(actx.hw)) level = 3;
  }
  return { level, amr, uv };
}

/** The enrolled device key (04||x||y, hex) from the stored enrollment attestation. */
export function enrolledDevicePoint(userRaw) {
  if (!['verified', 'token_only'].includes(userRaw?.attest_status)) return null;
  const jwt = userRaw.attest_jwt;
  if (typeof jwt !== 'string' || !jwt) return null;
  try {
    const h = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString());
    if (h?.jwk?.kty !== 'EC' || h.jwk.crv !== 'P-256') return null;
    const x = Buffer.from(h.jwk.x, 'base64url'), y = Buffer.from(h.jwk.y, 'base64url');
    if (x.length !== 32 || y.length !== 32) return null;
    return Buffer.concat([Buffer.from([4]), x, y]).toString('hex');
  } catch { return null; }
}

/** Short text for the page when the sign-in does not reach the required level. */
export function levelHint(required, viaPhone) {
  if (required >= 3) {
    return viaPhone
      ? 'This sign-in needs your fingerprint or PIN at the approval, on a phone that keeps the app key in hardware, with a genuine Encedo HEM.'
      : 'This sign-in needs a genuine Encedo HEM (attested at enrollment) and your passphrase or phone confirmation with fingerprint / PIN.';
  }
  if (required >= 2) return 'This sign-in needs you to confirm with your passphrase, or on a phone app protected with a PIN or fingerprint.';
  return 'This sign-in needs a HEM attested at enrollment.';
}

/**
 * Text for the page when the login context itself was unusable, so the level
 * hint ("confirm with your passphrase...") would point at the wrong cause.
 * null: the context was usable, or the cause is not the user's to fix.
 */
export function contextHint(reason) {
  if (reason === 'another_device' || reason === 'pubkey_mismatch') {
    return 'This HEM does not match the one recorded when your key was enrolled. Ask your administrator for a re-attestation link.';
  }
  if (reason === 'no_enrolled_device') {
    return 'Your key was enrolled without a hardware attestation. Ask your administrator for a re-attestation link.';
  }
  if (reason === 'no_attestation' || (reason && reason.includes('auth'))) {
    return 'Your HEM did not confirm the sign-in context. Its firmware may need an update.';
  }
  return null;
}
