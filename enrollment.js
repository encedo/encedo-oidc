import { HEM, HemError } from '/hem-sdk.js';

// Read token from URL fragment (#token=...) -- fragment is never sent to the server,
// so it won't appear in access logs or Referer headers.
const params = new URLSearchParams(window.location.hash.slice(1));
const token  = params.get('token') || '';

let userData = { sub: '', username: '' };

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('visible'));
  document.getElementById(id).classList.add('visible');
}

function showError(msg) {
  document.getElementById('error-msg').textContent = msg;
  showScreen('s-error');
}

// --- On load: validate token ----------------------------------
window.addEventListener('DOMContentLoaded', async () => {
  if (!token) return showError('No enrollment token provided.');

  try {
    const res  = await fetch('/enrollment/validate?token=' + encodeURIComponent(token));
    const data = await res.json();

    if (!res.ok) {
      showError(data.error === 'invalid_or_expired_token'
        ? 'This enrollment link has expired or was already used.'
        : data.error || 'Invalid link.');
      return;
    }

    userData = data;
    document.getElementById('f-username').textContent = data.username;
    document.getElementById('f-sub').textContent      = data.sub;
    if (data.hsm_url) document.getElementById('f-hsm-url').value = data.hsm_url;
    // challenge stored for use during submit -- must be signed with the new key
    userData.challenge = data.challenge;
    showScreen('s-form');

  } catch {
    showError('Network error -- make sure you are connected.');
  }
});

// --- Submit ---------------------------------------------------
async function doSubmit() {
  const hsm_url     = document.getElementById('f-hsm-url').value.trim();
  const password    = document.getElementById('f-password').value;
  const username    = document.getElementById('f-username').textContent.trim();
  const sub         = document.getElementById('f-sub').textContent.trim();
  const enrollToken = new URLSearchParams(location.hash.slice(1)).get('token');
  const formErr     = document.getElementById('form-err');
  const btn         = document.getElementById('submit-btn');

  if (!hsm_url) {
    formErr.textContent = 'Please enter the Encedo HSM URL.';
    return;
  }

  btn.disabled = true;
  formErr.textContent = '';

  const hem = new HEM(hsm_url);

  // Helper: authorize for a given scope (passphrase or mobile)
  async function authorize(scope, label) {
    if (password) {
      btn.textContent = label;
      return hem.authorizePassword(password, scope);
    } else {
      btn.textContent = label + ' (confirm on mobile...)';
      return hem.authorizeRemote(scope, {
        pollInterval: 2_000,
        pollTimeout:  60_000,
        onPending: () => console.debug(`[HEM] ${scope}: still waiting...`),
      });
    }
  }

  try {
    // -- Step 0: checkin -------------------------------------------
    btn.textContent = 'Connecting to HSM...';
    await hem.hemCheckin();

    // -- Step 1: authorize keymgmt:gen ----------------------------
    const genToken = await authorize('keymgmt:gen', 'Authorizing key generation...');

    // -- Step 2: create key pair -----------------------------------
    btn.textContent = 'Creating key...';
    const label    = `Encedo OIDC - ${username}`.slice(0, 32);
    const descrB64 = btoa(`ETSOIDC${sub}`);            // max 64 chars as base64
    const created  = await hem.createKeyPair(genToken, label, 'ED25519', descrB64);
    const kid      = created.kid;
    // For asymmetric keys, HSM derives kid = SHA-1(public key bytes) -- same as OIDC kid.
    // No separate derivation needed; backend will verify kid === SHA1(pubkey).
    if (!kid) throw new Error('No kid in createKeyPair response');

    // -- Step 3: authorize keymgmt:use:<kid> ----------------------
    const useToken = await authorize(`keymgmt:use:${kid}`, 'Authorizing key access...');

    // -- Step 4: fetch public key ----------------------------------
    btn.textContent = 'Fetching public key...';
    const keyInfo = await hem.getPubKey(useToken, kid);
    if (!keyInfo.pubkey) throw new Error('No pubkey in getKey response');
    // HSM returns pubkey as standard base64 -- backend expects raw 32-byte hex
    const pubkeyBytes = Uint8Array.from(atob(keyInfo.pubkey), c => c.charCodeAt(0));
    const pubkey      = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    // -- Step 5: sign the challenge -- key-possession proof ---------
    // Backend issued a challenge at /enrollment/validate.
    // Signing it proves we hold the private key, not just the public key.
    // HSM returns standard base64 -- convert to base64url for backend.
    btn.textContent = 'Signing challenge...';
    const challenge  = userData.challenge;
    if (!challenge) throw new Error('No challenge received from server -- call validate first');
    // exdsaSign returns Uint8Array (raw bytes) -- convert to base64url for backend
    const sigBytes  = await hem.exdsaSign(useToken, kid, challenge);
    const signature = btoa(String.fromCharCode(...sigBytes))
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // -- Step 6: HSM attestation -- hardware origin proof -----------
    // Any valid token accepted (scope irrelevant) -- useToken qualifies.
    // Returns { genuine, ... } where genuine is device attestation blob.
    // Backend validates genuine via api.encedo.com/attest (see src/services/attestation.js).
    // Failure is non-fatal: enrollment proceeds, hw_attested = false.
    btn.textContent = 'Fetching attestation...';
    let genuine = null;
    let crt     = null;
    try {
      const attData = await hem.getAttestation(useToken);
      genuine = attData.genuine ?? null;
      crt     = attData.crt     ?? null;
    } catch (e) {
      console.warn('[HEM] attestation failed (non-fatal):', e.message);
    }

    // -- Step 7: submit to backend ---------------------------------
    btn.textContent = 'Saving...';
    const res  = await fetch('/enrollment/submit', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token: enrollToken, hsm_url, kid, pubkey, signature, genuine, crt }),
    });
    const data = await res.json();

    if (!res.ok) {
      formErr.textContent =
        data.error === 'invalid_or_expired_token'
          ? 'Link has expired -- request a new one from your administrator.'
          : data.error || 'Submission failed.';
      btn.disabled = false;
      btn.textContent = 'Link HSM ->';
      return;
    }

    document.getElementById('s-username').textContent = data.username;
    document.getElementById('s-hsm').textContent      = hsm_url;
    showScreen('s-success');

  } catch (err) {
    console.error('[HEM] enrollment failed:', err);
    formErr.textContent = err instanceof HemError
      ? `HSM error (${err.code}): ${err.message}`
      : `Error: ${err.message}`;
    btn.disabled = false;
    btn.textContent = 'Link HSM ->';
  }
}

window.doSubmit = doSubmit;
