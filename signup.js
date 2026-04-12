import { HEM, HemError } from '/hem-sdk.js';

const token = location.hash.slice(1).replace(/^token=/, '');

let clientName           = '';
let clientRedirectOrigin = null;
let forcedKeyType        = null;
let lockedUsername       = null;

// --- Key type helpers -----------------------------------------

function hsmKeyType(keyType) {
  if (keyType === 'P256') return 'SECP256R1';
  if (keyType === 'P384') return 'SECP384R1';
  if (keyType === 'P521') return 'SECP521R1';
  return 'ED25519';
}

function exdsaAlg(keyType) {
  if (keyType === 'P256') return 'SHA256WithECDSA';
  if (keyType === 'P384') return 'SHA384WithECDSA';
  if (keyType === 'P521') return 'SHA512WithECDSA';
  return 'Ed25519';
}

function keyTypeLabel(keyType) {
  if (keyType === 'P256') return 'P-256 (ECDSA)';
  if (keyType === 'P384') return 'P-384 (ECDSA)';
  if (keyType === 'P521') return 'P-521 (ECDSA)';
  return 'Ed25519 (EdDSA)';
}

/**
 * Convert DER-encoded ECDSA signature to IEEE P1363 (r||s, fixed-width).
 * Handles both short-form (<= 127 bytes) and long-form (> 127 bytes, P-521) DER headers.
 */
function derToP1363(derBytes, keyType) {
  const n = { P256: 32, P384: 48, P521: 66 }[keyType];
  let pos = 1; // skip 0x30 SEQUENCE tag
  // Parse SEQUENCE length: long form if high bit set
  if (derBytes[pos] & 0x80) {
    pos += 1 + (derBytes[pos] & 0x7f);
  } else {
    pos += 1;
  }
  function readInt() {
    pos++;                              // skip 0x02 INTEGER tag
    const len = derBytes[pos++];
    const val = derBytes.slice(pos, pos + len);
    pos += len;
    const trimmed = val[0] === 0 ? val.slice(1) : val; // strip sign byte
    const out = new Uint8Array(n);
    out.set(trimmed, n - trimmed.length);               // right-align
    return out;
  }
  const r = readInt(), s = readInt();
  const out = new Uint8Array(n * 2);
  out.set(r, 0); out.set(s, n);
  return out;
}

// --- UI helpers -----------------------------------------------

function show(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('visible'));
  document.getElementById(id).classList.add('visible');
}

function setStatus(msg) {
  document.getElementById('su-status').textContent = msg;
}

function getSelectedKeyType() {
  if (forcedKeyType) return forcedKeyType;
  return document.getElementById('su-key-type')?.value || 'Ed25519';
}

// --- Init: validate invite token ------------------------------
if (!token) {
  show('s-invalid');
} else {
  try {
    const r = await fetch(`/signup/prefill?token=${encodeURIComponent(token)}`);
    if (!r.ok) { show('s-invalid'); }
    else {
      const d = await r.json();
      clientName    = d.client_name || 'this service';
      forcedKeyType = d.key_type || null;

      document.getElementById('rp-client-name').textContent = clientName;

      // Username: locked if admin pre-assigned it
      if (d.username) {
        lockedUsername = d.username;
        document.getElementById('su-username-row').style.display        = 'none';
        document.getElementById('su-username-locked-row').style.display = '';
        document.getElementById('su-username-locked-val').textContent   = d.username;
      } else {
        document.getElementById('su-username-row').style.display        = '';
        document.getElementById('su-username-locked-row').style.display = 'none';
      }

      if (d.name)  document.getElementById('su-name').value  = d.name;
      if (d.email) document.getElementById('su-email').value = d.email;

      // Key type: locked or selectable
      if (forcedKeyType) {
        document.getElementById('su-key-type-row').style.display        = 'none';
        document.getElementById('su-key-type-forced-row').style.display = '';
        document.getElementById('su-key-type-forced-label').textContent = keyTypeLabel(forcedKeyType);
      } else {
        document.getElementById('su-key-type-row').style.display        = '';
        document.getElementById('su-key-type-forced-row').style.display = 'none';
      }

      show('s-form');
      // Focus first editable field
      if (!lockedUsername) document.getElementById('su-username').focus();
      else if (!d.name)    document.getElementById('su-name').focus();
      else                 document.getElementById('su-email').focus();
    }
  } catch { show('s-invalid'); }
}

// --- Submit ---------------------------------------------------
async function doSubmit() {
  const btn = document.getElementById('su-submit-btn');
  const err = document.getElementById('su-err');
  err.textContent = '';

  const username = lockedUsername || document.getElementById('su-username').value.trim();
  const name     = document.getElementById('su-name').value.trim();
  const email    = document.getElementById('su-email').value.trim();
  const hsm_url  = document.getElementById('su-hsm-url').value.trim();
  const password = document.getElementById('su-password').value;
  const key_type = getSelectedKeyType();

  if (!username) { err.textContent = 'Username is required'; return; }
  if (!email)    { err.textContent = 'Email is required';    return; }
  if (!hsm_url)  { err.textContent = 'HSM URL is required';  return; }

  btn.disabled = true;
  show('s-enrolling');

  const hem = new HEM(hsm_url);

  async function authorize(scope) {
    return password
      ? hem.authorizePassword(password, scope)
      : hem.authorizeRemote(scope, { pollInterval: 2000, pollTimeout: 60000 });
  }

  try {
    setStatus('Connecting to HSM…');
    await hem.hemCheckin();

    setStatus('Authorizing key generation…');
    const genToken = await authorize('keymgmt:gen');

    setStatus('Creating account…');
    const regRes  = await fetch('/signup/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token, username, name, email, hsm_url, key_type }),
    });
    const regData = await regRes.json();
    if (!regRes.ok) {
      show('s-form');
      err.textContent = regData.error_description || regData.error || `Error ${regRes.status}`;
      btn.disabled = false;
      return;
    }

    const { sub, enrollment_token } = regData;
    clientRedirectOrigin = regData.client_redirect_origin;

    setStatus(`Creating ${keyTypeLabel(key_type)} key pair…`);
    const label    = `Encedo OIDC - ${username}`.slice(0, 32);
    const descrB64 = btoa(`ETSOIDC${sub}`);
    const hsmMode  = key_type !== 'Ed25519' ? 'ExDSA' : undefined;
    const created  = await hem.createKeyPair(genToken, label, hsmKeyType(key_type), descrB64, hsmMode);
    const kid      = created.kid;
    if (!kid) throw new Error('No kid in createKeyPair response');

    setStatus('Authorizing key access…');
    const useToken = await authorize(`keymgmt:use:${kid}`);

    setStatus('Fetching public key…');
    const keyInfo = await hem.getPubKey(useToken, kid);
    if (!keyInfo.pubkey) throw new Error('No pubkey in getKey response');
    const pubkeyBytes = Uint8Array.from(atob(keyInfo.pubkey), c => c.charCodeAt(0));
    const pubkey      = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    setStatus('Signing challenge…');
    const chalRes  = await fetch(`/enrollment/validate?token=${encodeURIComponent(enrollment_token)}`);
    const chalData = await chalRes.json();
    if (!chalRes.ok) throw new Error(chalData.error || 'Failed to get challenge');
    const rawSigBytes = await hem.exdsaSign(useToken, kid, chalData.challenge, exdsaAlg(key_type));
    const sigBytes    = key_type !== 'Ed25519' ? derToP1363(rawSigBytes, key_type) : rawSigBytes;
    const signature   = btoa(String.fromCharCode(...sigBytes))
                          .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    setStatus('Fetching attestation…');
    let genuine = null, crt = null;
    try {
      const att = await hem.getAttestation(useToken);
      genuine = att.genuine ?? null;
      crt     = att.crt     ?? null;
    } catch (e) { console.warn('[HEM] attestation non-fatal:', e.message); }

    setStatus('Saving…');
    const subRes  = await fetch('/enrollment/submit', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token: enrollment_token, hsm_url, kid, pubkey, key_type, signature, genuine, crt }),
    });
    const subData = await subRes.json();
    if (!subRes.ok) throw new Error(subData.error || 'Enrollment submission failed');

    document.getElementById('s-username').textContent = username;
    document.getElementById('s-client').textContent   = clientName;
    if (!clientRedirectOrigin) {
      document.getElementById('su-done-btn').style.display = 'none';
    }
    show('s-success');

  } catch (e) {
    console.error('[Signup] failed:', e);
    show('s-form');
    err.textContent = e instanceof HemError && e.code === 'http_401'
      ? 'Incorrect HSM passphrase.'
      : e instanceof HemError
      ? `HSM error: ${e.message}`
      : `Error: ${e.message}`;
    btn.disabled = false;
  }
}

window.doSubmit = doSubmit;

window.doGoToService = function() {
  if (clientRedirectOrigin) window.location.href = clientRedirectOrigin;
};
