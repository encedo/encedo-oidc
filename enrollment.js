import { HEM } from '/hem-sdk.js';
import { hsmKeyType, exdsaAlg, keyTypeLabel, derToP1363, bytesToBase64url, bytesToHex, base64ToBytes, fetchJson, hemErrMsg, authorizeScope } from '/hsm-common.js';

// Read token from URL fragment (#token=...) -- fragment is never sent to the server,
// so it won't appear in access logs or Referer headers.
const params     = new URLSearchParams(window.location.hash.slice(1));
const token      = params.get('token') || '';
const emailNonce = params.get('n') || '';   // present when arriving via the emailed link

let userData = { sub: '', username: '' };
let clientRedirectOrigin = null;
let createdKid = null;   // key pair from an earlier attempt on this page -- reused, not cloned

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
    let data;
    try {
      data = await fetchJson('/enrollment/validate?token=' + encodeURIComponent(token));
    } catch (e) {
      if (!e.status) throw e;
      showError(e.code === 'invalid_or_expired_token'
        ? 'This enrollment link has expired or was already used.'
        : e.message);
      return;
    }

    userData = data;
    clientRedirectOrigin = data.client_redirect_origin ?? null;
    document.getElementById('f-username').textContent = data.username;
    document.getElementById('f-sub').textContent      = data.sub;
    if (data.hsm_url) document.getElementById('f-hsm-url').value = data.hsm_url;
    userData.challenge = data.challenge;

    // Key type: if admin forced it, hide selector and show info label
    const forcedKeyType = data.forced_key_type;
    const ktField  = document.getElementById('key-type-field');
    const ktSelect = document.getElementById('f-key-type');
    const ktForced = document.getElementById('key-type-forced');

    if (forcedKeyType) {
      ktField.style.display  = 'none';
      ktForced.style.display = '';
      document.getElementById('key-type-forced-label').textContent = keyTypeLabel(forcedKeyType);
      userData.key_type = forcedKeyType;
    } else {
      ktField.style.display  = '';
      ktForced.style.display = 'none';
      userData.key_type = ktSelect.value; // default from select
      ktSelect.addEventListener('change', () => { userData.key_type = ktSelect.value; });
    }

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
  const key_type    = userData.key_type || 'Ed25519';

  if (!hsm_url) {
    formErr.textContent = 'Please enter the Encedo HSM URL.';
    return;
  }

  if (btn.disabled) return;
  btn.disabled = true;
  formErr.textContent = '';

  const hem = new HEM(hsm_url);

  // Helper: authorize for a given scope (passphrase or mobile)
  function authorize(scope, label) {
    btn.textContent = password ? label : label + ' (confirm on mobile...)';
    return authorizeScope(hem, password, scope, { onPending: () => console.debug(`[HEM] ${scope}: still waiting...`) });
  }

  try {
    // -- Step 0: checkin -------------------------------------------
    btn.textContent = 'Connecting to HSM...';
    await hem.hemCheckin();

    // -- Step 1+2: create key pair (once -- a retry reuses the kid) ----
    let kid = createdKid;
    if (!kid) {
      const genToken = await authorize('keymgmt:gen', 'Authorizing key generation...');
      btn.textContent = `Creating ${keyTypeLabel(key_type)} key...`;
      const label    = `Encedo OIDC - ${username}`.slice(0, 32);
      const descrB64 = btoa(`ETSOIDC${sub}`);
      const hsmMode  = key_type !== 'Ed25519' ? 'ExDSA' : undefined;
      const created  = await hem.createKeyPair(genToken, label, hsmKeyType(key_type), descrB64, hsmMode);
      kid = created.kid;
      if (!kid) throw new Error('No kid in createKeyPair response');
      createdKid = kid;
    }

    // -- Step 3: authorize keymgmt:use:<kid> ----------------------
    const useToken = await authorize(`keymgmt:use:${kid}`, 'Authorizing key access...');

    // -- Step 4: fetch public key ----------------------------------
    btn.textContent = 'Fetching public key...';
    const keyInfo = await hem.getPubKey(useToken, kid);
    if (!keyInfo.pubkey) throw new Error('No pubkey in getKey response');
    // HSM returns pubkey as standard base64 -- convert to hex
    const pubkey = bytesToHex(base64ToBytes(keyInfo.pubkey));

    // -- Step 5: sign the challenge -- key-possession proof ---------
    btn.textContent = 'Signing challenge...';
    const challenge  = userData.challenge;
    if (!challenge) throw new Error('No challenge received from server -- call validate first');
    const rawSigBytes = await hem.exdsaSign(useToken, kid, challenge, exdsaAlg(key_type));
    const sigBytes  = key_type !== 'Ed25519' ? derToP1363(rawSigBytes, key_type) : rawSigBytes;
    const signature = bytesToBase64url(sigBytes);

    // -- Step 6: HSM attestation -- hardware origin proof -----------
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
    let data;
    try {
      data = await fetchJson('/enrollment/submit', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ token: enrollToken, hsm_url, kid, pubkey, key_type, signature, genuine, crt, n: emailNonce }),
      });
    } catch (e) {
      if (!e.status) throw e;
      formErr.textContent = e.code === 'invalid_or_expired_token'
        ? 'Link has expired -- request a new one from your administrator.'
        : e.message;
      btn.disabled = false;
      btn.textContent = 'Link HSM ->';
      return;
    }

    document.getElementById('s-username').textContent = data.username;
    document.getElementById('s-hsm').textContent      = hsm_url;
    if (!clientRedirectOrigin) {
      // Admin-triggered enrollment (no service to return to): offer to close the tab.
      document.getElementById('s-done-btn').style.display  = 'none';
      document.getElementById('s-close-btn').style.display = 'block';
    }
    showScreen('s-success');

  } catch (err) {
    console.error('[HEM] enrollment failed:', err);
    formErr.textContent = err.status ? err.message : hemErrMsg(err);
    btn.disabled = false;
    btn.textContent = 'Link HSM ->';
  } finally {
    try { hem.clearKeys(); } catch { /* SDK without clearKeys */ }
  }
}

function doGoToService() {
  if (clientRedirectOrigin) window.location.href = clientRedirectOrigin;
}

function doClose() {
  window.close();
  // Browsers refuse window.close() for a tab the script did not open (the usual
  // case here -- the admin opened the link). If we're still on the page shortly
  // after, swap the button for a hint telling the user to close it themselves.
  setTimeout(() => {
    document.getElementById('s-close-btn').style.display  = 'none';
    document.getElementById('s-close-hint').style.display = 'block';
  }, 200);
}

// Click dispatch -- data-action instead of inline handlers (CSP).
const ACTIONS = {
  'do-submit':        () => doSubmit(),
  'do-go-to-service': () => doGoToService(),
  'do-close':         () => doClose(),
};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  const fn = el && ACTIONS[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el); }
});
