import { HEM } from '/hem-sdk.js';
import { hsmKeyType, exdsaAlg, keyTypeLabel, derToP1363, bytesToBase64url, bytesToHex, base64ToBytes, fetchJson, hemErrMsg, authorizeScope } from '/hsm-common.js';

// Fragment carries token and, for an emailed invite, the email nonce (#token=...&n=...).
// Parse both properly -- a naive strip would fold "&n=..." into the token.
const hashParams  = new URLSearchParams(location.hash.slice(1));
const token       = hashParams.get('token') || '';
const emailNonce  = hashParams.get('n') || '';

let clientName           = '';
let clientRedirectOrigin = null;
let forcedKeyType        = null;
let lockedUsername       = null;

// What an earlier attempt already achieved. /signup/register consumes the
// one-time invite and creates the account, so once it has succeeded a retry
// must NOT call it again (the invite is gone: 404 invite_not_found); it picks
// up at the HSM steps with the same sub/enrollment_token. Likewise a key pair
// created on the device is reused rather than cloned on every retry.
let progress = null;   // { sub, enrollment_token, username, key_type, kid? }

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
    let d;
    try { d = await fetchJson(`/signup/prefill?token=${encodeURIComponent(token)}`); } catch { d = null; }
    if (!d) { show('s-invalid'); }
    else {
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

      // Email: pinned by the admin at invite time (H1), so it is read-only here --
      // the backend ignores any email in the request body regardless.
      document.getElementById('su-email').value = d.email ?? '';
      if (d.email) {
        document.getElementById('su-email-row').style.display        = 'none';
        document.getElementById('su-email-locked-row').style.display = '';
        document.getElementById('su-email-locked-val').textContent   = d.email;
      } else {
        document.getElementById('su-email-row').style.display        = '';
        document.getElementById('su-email-locked-row').style.display = 'none';
      }

      // Arrived via the emailed link -> the click itself proves mailbox access.
      if (emailNonce) document.getElementById('su-email-verified').style.display = 'flex';

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
  if (btn.disabled) return;
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
  const authorize = scope => authorizeScope(hem, password, scope);

  try {
    setStatus('Connecting to HSM…');
    await hem.hemCheckin();

    let sub, enrollment_token, kid;
    if (progress) {
      // The account exists from a previous attempt -- resume at the HSM steps.
      ({ sub, enrollment_token, kid } = progress);
      setStatus('Account already created — resuming HSM setup…');
    } else {
      // Key generation is authorized BEFORE the invite is consumed, so a wrong
      // passphrase or a declined push costs nothing on the server side.
      setStatus('Authorizing key generation…');
      await authorize('keymgmt:gen');

      setStatus('Creating account…');
      const regData = await fetchJson('/signup/register', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ token, username, name, email, hsm_url, key_type, n: emailNonce }),
      });
      ({ sub, enrollment_token } = regData);
      clientRedirectOrigin = regData.client_redirect_origin;
      progress = { sub, enrollment_token, username, key_type };
    }

    if (!kid) {
      setStatus(`Creating ${keyTypeLabel(progress.key_type)} key pair…`);
      const genToken = await authorize('keymgmt:gen');   // cached by the SDK when already granted
      const label    = `Encedo OIDC - ${username}`.slice(0, 32);
      const descrB64 = btoa(`ETSOIDC${sub}`);
      const hsmMode  = progress.key_type !== 'Ed25519' ? 'ExDSA' : undefined;
      const created  = await hem.createKeyPair(genToken, label, hsmKeyType(progress.key_type), descrB64, hsmMode);
      kid = created.kid;
      if (!kid) throw new Error('No kid in createKeyPair response');
      progress.kid = kid;
    }
    const kt = progress.key_type;

    setStatus('Authorizing key access…');
    const useToken = await authorize(`keymgmt:use:${kid}`);

    setStatus('Fetching public key…');
    const keyInfo = await hem.getPubKey(useToken, kid);
    if (!keyInfo.pubkey) throw new Error('No pubkey in getKey response');
    const pubkey = bytesToHex(base64ToBytes(keyInfo.pubkey));

    setStatus('Signing challenge…');
    const chalData = await fetchJson(`/enrollment/validate?token=${encodeURIComponent(enrollment_token)}`);
    const rawSigBytes = await hem.exdsaSign(useToken, kid, chalData.challenge, exdsaAlg(kt));
    const sigBytes    = kt !== 'Ed25519' ? derToP1363(rawSigBytes, kt) : rawSigBytes;
    const signature   = bytesToBase64url(sigBytes);

    setStatus('Fetching attestation…');
    let genuine = null, crt = null;
    try {
      const att = await hem.getAttestation(useToken);
      genuine = att.genuine ?? null;
      crt     = att.crt     ?? null;
    } catch (e) { console.warn('[HEM] attestation non-fatal:', e.message); }

    setStatus('Saving…');
    try {
      await fetchJson('/enrollment/submit', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ token: enrollment_token, hsm_url, kid, pubkey, key_type: kt, signature, genuine, crt }),
      });
    } catch (e) {
      if (e.code === 'invalid_or_expired_token') {
        // The one-time enrollment token is gone but the account exists: only
        // the administrator can issue a new link. Say exactly that.
        progress = null;
        throw new Error(`Your account "${username}" was created, but the HSM link could not be saved and the enrollment link is now used up. Ask your administrator for a new enrollment link.`);
      }
      throw e;
    }

    document.getElementById('s-username').textContent = username;
    document.getElementById('s-client').textContent   = clientName;
    if (!clientRedirectOrigin) {
      document.getElementById('su-done-btn').style.display = 'none';
    }
    show('s-success');

  } catch (e) {
    console.error('[Signup] failed:', e);
    show('s-form');
    err.textContent = (progress ? 'Account created — HSM setup did not finish: ' : '') + (e.status ? e.message : hemErrMsg(e))
      + (progress ? ' Fix the problem and press the button again to resume.' : '');
    btn.disabled = false;
  } finally {
    try { hem.clearKeys(); } catch { /* SDK without clearKeys */ }
  }
}

function doGoToService() {
  if (clientRedirectOrigin) window.location.href = clientRedirectOrigin;
}

// Click dispatch -- data-action instead of inline handlers (CSP).
const ACTIONS = {
  'do-submit':        () => doSubmit(),
  'do-go-to-service': () => doGoToService(),
};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  const fn = el && ACTIONS[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el); }
});
