// Re-attestation of an enrolled key (HEM firmware 1.3): the user opens the
// admin's link, authorizes on the HEM (passphrase or phone) and the module
// attests the key it already holds -- same kid, nothing else changes.
import { HEM } from '/hem-sdk.js';
import { ensureLocalNetwork } from '/local-network.js';
import { fetchJson, hemErrMsg, authorizeScope, attestKey, hemOptions } from '/hsm-common.js';

// Token in the URL fragment: never sent to the server, never in access logs or Referer.
const token = new URLSearchParams(window.location.hash.slice(1)).get('token') || '';
let data = null;

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('visible'));
  document.getElementById(id).classList.add('visible');
}
function showError(msg) {
  document.getElementById('error-msg').textContent = msg;
  showScreen('s-error');
}

const LINK_ERRORS = {
  invalid_or_expired_token: 'This link has expired or was already used. Ask your administrator for a new one.',
  key_changed:              'Your key has changed since this link was issued. Ask your administrator for a new one.',
  user_not_found:           'This account no longer exists.',
};

window.addEventListener('DOMContentLoaded', async () => {
  if (!token) return showError('No token in the link.');
  try {
    data = await fetchJson('/reattest/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  } catch (e) {
    return showError(e.status ? (LINK_ERRORS[e.code] ?? e.message) : 'Network error -- make sure you are connected.');
  }
  document.getElementById('f-username').textContent = data.username;
  document.getElementById('f-kid').textContent      = data.kid;
  if (data.hsm_url) document.getElementById('f-hsm-url').value = data.hsm_url;
  showScreen('s-form');
});

const RESULT = {
  verified:   'Genuine Encedo HEM, key generated inside it',
  token_only: 'Key generated inside the module (device origin not proven)',
};

async function doSubmit() {
  const hsm_url  = document.getElementById('f-hsm-url').value.trim();
  const password = document.getElementById('f-password').value;
  const formErr  = document.getElementById('form-err');
  const btn      = document.getElementById('submit-btn');
  if (!hsm_url) { formErr.textContent = 'Please enter the Encedo HSM URL.'; return; }
  if (btn.disabled) return;
  btn.disabled = true;
  formErr.textContent = '';
  const reset = () => { btn.disabled = false; btn.textContent = 'Confirm →'; };

  const hem = new HEM(hsm_url, hemOptions());
  try {
    btn.textContent = 'Connecting to HSM...';
    await ensureLocalNetwork(hsm_url);   // Chromium asks the user before a public page reaches a local device
    await hem.hemCheckin();

    btn.textContent = password ? 'Authorizing...' : 'Authorizing (confirm on mobile...)';
    const useToken = await authorizeScope(hem, password, `keymgmt:use:${data.kid}`);

    btn.textContent = 'Attesting key...';
    const { attestation, crt, error } = await attestKey(hem, useToken, data.kid, data.attest);
    if (!attestation) throw Object.assign(new Error(`The module did not attest the key (${error}).`), { code: 'attest_failed' });

    btn.textContent = 'Saving...';
    let r;
    try {
      r = await fetchJson('/reattest/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, attestation, crt }) });
    } catch (e) {
      if (!e.status) throw e;
      formErr.textContent = LINK_ERRORS[e.code] ?? e.message;
      return reset();
    }
    document.getElementById('s-username').textContent = r.username;
    document.getElementById('s-result').textContent   = RESULT[r.attest_status] ?? r.attest_status;
    showScreen('s-success');
  } catch (err) {
    console.error('[HEM] re-attestation failed:', err);
    formErr.textContent = err.code === 'attest_failed' || err.status ? err.message : hemErrMsg(err);
    reset();
  } finally {
    try { hem.clearKeys(); } catch { /* SDK without clearKeys */ }
  }
}

function doClose() {
  window.close();
  // A tab the script did not open cannot be closed by it: say so instead.
  setTimeout(() => {
    document.getElementById('s-close-btn').style.display  = 'none';
    document.getElementById('s-close-hint').style.display = 'block';
  }, 200);
}

// A real form submission: password managers offer to save / fill the passphrase.
document.getElementById('reattest-form').addEventListener('submit', e => { e.preventDefault(); doSubmit(); });

// Click dispatch -- data-action instead of inline handlers (CSP).
const ACTIONS = { 'do-close': () => doClose() };
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  const fn = el && ACTIONS[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el); }
});
