import { HEM, HemError } from '/hem-sdk.js';

// --- Key type helpers -----------------------------------------

/** Maps key_type to exdsaSign alg string for Encedo HSM API. */
function exdsaAlg(keyType) {
  if (keyType === 'P256') return 'SHA256WithECDSA';
  if (keyType === 'P384') return 'SHA384WithECDSA';
  if (keyType === 'P521') return 'SHA512WithECDSA';
  return 'Ed25519'; // Ed25519 (default / legacy)
}

function derToP1363(derBytes, keyType) {
  const n = { P256: 32, P384: 48, P521: 66 }[keyType];
  let pos = 1;
  pos += derBytes[pos] & 0x80 ? 1 + (derBytes[pos] & 0x7f) : 1;
  function readInt() {
    pos++;
    const len = derBytes[pos++];
    const val = derBytes.slice(pos, pos + len);
    pos += len;
    const trimmed = val[0] === 0 ? val.slice(1) : val;
    const out = new Uint8Array(n);
    out.set(trimmed, n - trimmed.length);
    return out;
  }
  const r = readInt(), s = readInt();
  const out = new Uint8Array(n * 2);
  out.set(r, 0); out.set(s, n);
  return out;
}

/** Human-readable algorithm label for UI. */
function keyTypeDisplay(keyType) {
  if (keyType === 'P256') return 'ES256 / P-256';
  if (keyType === 'P384') return 'ES384 / P-384';
  if (keyType === 'P521') return 'ES512 / P-521';
  return 'EdDSA / Ed25519';
}

// --- OIDC params --------------------------------------
const params = new URLSearchParams(window.location.search);
const OIDC = {
  client_id:             params.get('client_id')            || '',
  redirect_uri:          params.get('redirect_uri')         || '',
  response_type:         params.get('response_type')        || 'code',
  scope:                 params.get('scope')                 || 'openid',
  state:                 params.get('state')                 || '',
  nonce:                 params.get('nonce')                 || '',
  code_challenge:        params.get('code_challenge')        || '',
  code_challenge_method: params.get('code_challenge_method') || '',
};

// --- Session (in-memory only) -------------------------
let session = {
  session_id:      null,
  signing_input:   null,
  user_name:       null,
  user_username:   null,
  hsm_url:         null,
  password:        null,
  hem:             null,   // HEM instance
  listToken:       null,   // keymgmt:search token
  selectedKey:     null,   // { kid, label, sub }
  useToken:        null,
  openSearch:      false,  // HSM allows unauthenticated search
  hasMobileApp:    false,  // HSM has mobile-app keys (^RVhUQUlE)
  pendingAfterPin: null,   // 'search' | 'use'
  pendingSign:     null,   // { useToken, kid, label, loginData } -- set before s-token-confirm
};

// Used to cancel stale async mobile-auth operations
let currentOpId = null;
let mobileAbortCtrl = null;
let fasttrackActive = false;

// --- localStorage helpers -----------------------------
const LS_HSM_URL  = 'encedo_oidc_hsm_url';

function lsSaveHints(hsmUrl) {
  try {
    if (hsmUrl) localStorage.setItem(LS_HSM_URL, hsmUrl);
    const dl    = document.getElementById('hsm-url-list');
    const saved = localStorage.getItem(LS_HSM_URL);
    if (saved && dl) dl.innerHTML = `<option value="${saved}">`;
  } catch {}
}

function lsRestoreHints() {
  try {
    const h = localStorage.getItem(LS_HSM_URL);
    if (h) {
      document.getElementById('hsm-url-input').value = h;
      const dl = document.getElementById('hsm-url-list');
      if (dl) dl.innerHTML = `<option value="${h}">`;
    }
  } catch {}
}

// --- Fasttrack cache (per redirect_uri) ---------------
function ftKey() { return 'encedo_ft_' + OIDC.redirect_uri; }

function ftLoad() {
  try { return JSON.parse(localStorage.getItem(ftKey()) || 'null'); } catch { return null; }
}

function ftSave(patch) {
  try {
    const cur = ftLoad() || {};
    localStorage.setItem(ftKey(), JSON.stringify({ ...cur, ...patch }));
  } catch {}
}

function ftClear() {
  try {
    const cur = ftLoad();
    if (cur) {
      delete cur.kid; delete cur.label; delete cur.sub;
      localStorage.setItem(ftKey(), JSON.stringify(cur));
    }
  } catch {}
}

function ftRestoreUI() {
  const cache = ftLoad();
  if (!cache?.kid) return;
  const row = document.getElementById('ft-row');
  if (row) row.style.display = '';
  const lbl = document.getElementById('ft-key-label');
  if (lbl) lbl.textContent = cache.label || cache.kid;
  const cb = document.getElementById('ft-checkbox');
  if (cb) cb.checked = !!cache.fasttrack;
  if (cache.hsmUrl) document.getElementById('hsm-url-input').value = cache.hsmUrl;
}

// --- Init ---------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  try {
    const rpHost = new URL(OIDC.redirect_uri).hostname;
    document.getElementById('rp-label-login').textContent = rpHost;
    document.getElementById('confirm-rp').textContent     = rpHost;
    document.getElementById('sign-audience').textContent  = rpHost;
  } catch {
    const label = OIDC.client_id || 'Unknown client';
    document.getElementById('rp-label-login').textContent = label;
    document.getElementById('rp-label-pin').textContent   = label;
  }

  lsRestoreHints();
  ftRestoreUI();

  document.getElementById('hsm-url-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('pin-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') doSubmitPin();
  });
});

// --- Screen switching ---------------------------------
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('visible'));
  document.getElementById(id).classList.add('visible');
}

// --- Step 1: Login -> HSM checkin -> detect capabilities -> search keys -----
async function doLogin() {
  const hsmUrl = document.getElementById('hsm-url-input').value.trim();
  if (!hsmUrl) {
    document.getElementById('login-err').textContent = 'Please enter the HSM URL.';
    return;
  }

  const btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.textContent = 'Connecting...';
  document.getElementById('login-err').textContent = '';

  try {
    session.hsm_url  = hsmUrl;
    session.password = null;
    lsSaveHints(hsmUrl);

    const hem = new HEM(hsmUrl);
    session.hem = hem;
    btn.textContent = 'Connecting to HSM...';
    await hem.hemCheckin();

    // Step A: detect mobile-app support (^RVhUQUlE pattern)
    btn.textContent = 'Detecting HSM capabilities...';
    try {
      const mobileKeys = await hem.searchKeys(null, '^RVhUQUlE');
      session.openSearch   = true;
      session.hasMobileApp = mobileKeys.length > 0;
    } catch (e) {
      if (!e.status || e.status < 400 || e.status >= 500) throw e;
      // 4xx -> HSM requires auth for search
      session.openSearch   = false;
      session.hasMobileApp = false;
    }

    // Fasttrack: skip key search + confirm screen if enabled
    const ftCache = ftLoad();
    const ftEnabled = !!(ftCache?.kid && document.getElementById('ft-checkbox')?.checked);
    ftSave({ hsmUrl, fasttrack: ftEnabled });

    if (ftEnabled) {
      const ok = await tryFasttrack(ftCache.kid, ftCache.label || '', ftCache.sub || null, btn);
      if (ok) return;
      // fallthrough to normal key search on failure
    }

    // Step B: search OIDC keys (or delegate to passphrase screen)
    if (session.openSearch) {
      btn.textContent = 'Searching keys...';
      const keys = await hem.searchKeys(null, '^' + btoa('ETSOIDC'));
      if (keys.length === 0) {
        document.getElementById('login-err').textContent =
          'No OIDC keys found on this HSM. Please complete enrollment first.';
        btn.disabled = false;
        btn.textContent = 'Continue ->';
        return;
      }
      renderKeyList(keys);
      btn.disabled = false;
      btn.textContent = 'Continue ->';
      if (keys.length === 1) doSelectKey();
      else showScreen('s-keys');
    } else {
      // Need passphrase before we can search
      session.pendingAfterPin = 'search';
      btn.disabled = false;
      btn.textContent = 'Continue ->';
      showPinScreen();
    }

  } catch (err) {
    console.error('[doLogin]', err);
    document.getElementById('login-err').textContent = hemErrMsg(err);
    btn.disabled = false;
    btn.textContent = 'Continue ->';
  }
}

// --- Fasttrack: skip key selection + confirm screen ---
async function tryFasttrack(kid, label, sub, btn) {
  try {
    btn.textContent = 'Fast track\u2026';
    fasttrackActive = true;
    const loginRes = await fetch('/authorize/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ sub, ...OIDC }),
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok) throw new Error(loginData.error_description || loginData.error || 'Login failed');

    session.selectedKey = { kid, label, sub };
    session.pendingSign = { kid, label, loginData };
    btn.disabled = false;
    btn.textContent = 'Continue \u2192';
    await doApproveSign();
    return true;
  } catch (err) {
    console.warn('[fasttrack] failed, clearing cache and falling back:', err);
    fasttrackActive = false;
    ftClear();
    document.getElementById('ft-row').style.display = 'none';
    btn.textContent = 'Searching keys\u2026';
    return false;
  }
}

// --- Passphrase screen helper -------------------------
function showPinScreen() {
  document.getElementById('pin-err').textContent = '';
  document.getElementById('pin-input').value = '';
  showScreen('s-pin');
  setTimeout(() => document.getElementById('pin-input').focus(), 100);
}

// --- Step passphrase: user submitted passphrase -------
async function doSubmitPin() {
  const pin = document.getElementById('pin-input').value;
  if (!pin) {
    document.getElementById('pin-err').textContent = 'Please enter your passphrase.';
    return;
  }

  const btn = document.getElementById('pin-btn');
  btn.disabled = true;
  btn.textContent = 'Authorizing...';
  document.getElementById('pin-err').textContent = '';

  try {
    session.password = pin;

    if (session.pendingAfterPin === 'search') {
      // Authorize + search OIDC keys
      const listToken = await session.hem.authorizePassword(pin, 'keymgmt:search');
      session.listToken = listToken;
      btn.textContent = 'Searching keys...';
      const keys = await session.hem.searchKeys(listToken, '^' + btoa('ETSOIDC'));
      if (keys.length === 0) {
        document.getElementById('pin-err').textContent =
          'No OIDC keys found on this HSM. Please complete enrollment first.';
        btn.disabled = false;
        btn.textContent = 'Continue ->';
        return;
      }
      renderKeyList(keys);
      btn.disabled = false;
      btn.textContent = 'Continue ->';
      if (keys.length === 1) doSelectKey();
      else showScreen('s-keys');

    } else if (session.pendingAfterPin === 'approve') {
      // Passphrase for signing -- authorize + complete sign
      const { kid, label, loginData } = session.pendingSign;
      const scope = `keymgmt:use:${kid}`;
      const useToken = await session.hem.authorizePassword(pin, scope);
      btn.disabled = false;
      btn.textContent = 'Continue \u2192';
      await doCompleteSign(useToken, kid, label, loginData);
    }

  } catch (err) {
    console.error('[doSubmitPin]', err);
    document.getElementById('pin-err').textContent = hemErrMsg(err);
    btn.disabled = false;
    btn.textContent = 'Continue ->';
  }
}

// --- Key list rendering -------------------------------
/** Decode key description (Uint8Array) -> sub string or null */
function extractSub(description) {
  if (!description) return null;
  try {
    const text   = new TextDecoder().decode(description);
    const PREFIX = 'ETSOIDC';
    return text.startsWith(PREFIX) ? text.slice(PREFIX.length) : null;
  } catch { return null; }
}

function renderKeyList(keys) {
  const sel = document.getElementById('key-select');
  sel.innerHTML = '';

  if (keys.length === 0) {
    const opt = document.createElement('option');
    opt.textContent = '-- no keys found --';
    opt.disabled = true;
    sel.appendChild(opt);
    session.selectedKey = null;
    return;
  }

  keys.forEach(k => {
    const sub = extractSub(k.description);
    const opt = document.createElement('option');
    opt.value         = k.kid;
    opt.textContent   = (k.label || '(no label)') + '  /  ' + k.kid;
    opt.dataset.label = k.label || '';
    opt.dataset.sub   = sub || '';
    sel.appendChild(opt);
  });

  // Pre-select first
  const first = keys[0];
  session.selectedKey = { kid: first.kid, label: first.label, sub: extractSub(first.description) };

  sel.addEventListener('change', () => {
    const opt = sel.selectedOptions[0];
    session.selectedKey = { kid: opt.value, label: opt.dataset.label, sub: opt.dataset.sub || null };
  });
}

// --- Step 2: Key selected -> POST login -> show claims confirmation -----
async function doSelectKey() {
  const sel = document.getElementById('key-select');
  if (sel.value) {
    const opt = sel.selectedOptions[0];
    session.selectedKey = { kid: sel.value, label: opt?.dataset.label || '', sub: opt?.dataset.sub || null };
  }
  if (!session.selectedKey?.kid) {
    document.getElementById('keys-err').textContent = 'Please select a key.';
    return;
  }

  const btn = document.getElementById('keys-next-btn');
  btn.disabled = true;
  btn.textContent = 'Loading\u2026';
  document.getElementById('keys-err').textContent = '';

  const { kid, label } = session.selectedKey;

  try {
    const sub = session.selectedKey?.sub || null;
    const loginRes = await fetch('/authorize/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ sub, ...OIDC }),
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok) throw new Error(loginData.error_description || loginData.error || 'Login failed');

    // Decode JWT payload and populate confirm screen
    const payload = decodeJwtPayload(loginData.signing_input);
    document.getElementById('tc-username').textContent = loginData.user_username || '';
    document.getElementById('tc-audience').textContent = loginData.client_name || payload?.aud || OIDC.client_id;
    document.getElementById('tc-iss').textContent      = payload?.iss || '';
    document.getElementById('tc-iat').textContent      = payload?.iat ? fmtTs(payload.iat) : '\u2014';
    document.getElementById('tc-exp').textContent      = payload?.exp ? fmtTs(payload.exp) : '\u2014';

    const extra = document.getElementById('tc-extra');
    extra.innerHTML = '';
    const CLAIM_LABELS = { preferred_username: 'username' };
    for (const key of ['preferred_username', 'name', 'email']) {
      if (payload?.[key]) {
        const row = document.createElement('div');
        row.className = 'info-row';
        const k = document.createElement('span'); k.className = 'info-key';   k.textContent = CLAIM_LABELS[key] ?? key;
        const v = document.createElement('span'); v.className = 'info-value'; v.textContent = payload[key];
        row.append(k, v);
        extra.appendChild(row);
      }
    }

    session.pendingSign = { kid, label, loginData };
    btn.disabled = false;
    btn.textContent = 'Next \u2192';
    showScreen('s-token-confirm');

  } catch (err) {
    console.error('[doSelectKey]', err);
    document.getElementById('keys-err').textContent = hemErrMsg(err);
    btn.disabled = false;
    btn.textContent = 'Next \u2192';
  }
}

// --- Cancel mobile auth -> switch to passphrase --------
function doCancelMobile() {
  currentOpId = null; // invalidate pending mobile operation
  mobileAbortCtrl?.abort(); mobileAbortCtrl = null; // stop broker polling
  // TODO: call broker mobile authorization cancellation endpoint here (e.g. DELETE {broker}/notify/event/{eventid})
  document.getElementById('cancel-mobile-btn').style.display = 'none';
  if (session.password) {
    doApproveSign(); // retry with cached passphrase
  } else {
    session.pendingAfterPin = 'approve';
    showPinScreen();
  }
}

// --- JWT helpers --------------------------------------
function decodeJwtPayload(signingInput) {
  try {
    const b64 = signingInput.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(b64));
  } catch { return null; }
}

function fmtTs(unixSec) {
  return new Date(unixSec * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

// --- Step 3: Approve -> authorize HSM key --------------
async function doApproveSign() {
  const btn = document.getElementById('tc-approve-btn');
  btn.disabled = true;
  btn.textContent = 'Authorizing\u2026';

  const { kid, label, loginData } = session.pendingSign;
  const scope = `keymgmt:use:${kid}`;
  const opId  = Symbol();
  currentOpId = opId;

  try {
    let useToken;

    if (session.password) {
      useToken = await session.hem.authorizePassword(session.password, scope);
      if (currentOpId !== opId) return;

    } else if (session.hasMobileApp) {
      document.getElementById('sign-title').textContent     = 'Waiting for approval\u2026';
      document.getElementById('sign-status').textContent    = 'Confirm on your mobile device';
      document.getElementById('sign-username').textContent  = loginData.user_username;
      document.getElementById('sign-keysource').textContent = `HSM \u00b7 ${label}`;
      document.getElementById('sign-algorithm').textContent = keyTypeDisplay(loginData.key_type);
      document.getElementById('cancel-mobile-btn').style.display  = '';
      document.getElementById('cancel-redirect-btn').style.display = 'none';
      showScreen('s-signing');

      mobileAbortCtrl = new AbortController();
      useToken = await session.hem.authorizeRemote(scope, {
        pollInterval: 2_000, pollTimeout: 60_000,
        onPending: () => console.debug(`[HEM] ${scope}: waiting\u2026`),
        signal: mobileAbortCtrl.signal,
      });
      mobileAbortCtrl = null;
      if (currentOpId !== opId) return;

      document.getElementById('cancel-mobile-btn').style.display = 'none';

    } else {
      session.pendingAfterPin = 'approve';
      btn.disabled = false;
      btn.textContent = 'Approve \u2192';
      showPinScreen();
      return;
    }

    await doCompleteSign(useToken, kid, label, loginData);

  } catch (err) {
    if (currentOpId !== opId) return;
    console.error('[doApproveSign]', err);
    btn.disabled = false;
    btn.textContent = 'Approve \u2192';
    showError(hemErrMsg(err));
  }
}

// Used to cancel the post-sign redirect countdown
let cancelRedirect = null;

// --- Step 4: HSM sign + POST confirm + countdown ------
async function doCompleteSign(useToken, kid, label, loginData) {
  document.getElementById('sign-title').textContent     = 'Confirmed';
  document.getElementById('sign-status').textContent    = 'Generating cryptographic signature\u2026';
  document.getElementById('sign-username').textContent  = loginData.user_username;
  document.getElementById('sign-keysource').textContent = `HSM \u00b7 ${label}`;
  document.getElementById('sign-algorithm').textContent = keyTypeDisplay(loginData.key_type);
  document.getElementById('cancel-mobile-btn').style.display  = 'none';
  document.getElementById('cancel-redirect-btn').style.display = 'none';
  showScreen('s-signing');

  try {
    const rawSigBytes = await session.hem.exdsaSign(useToken, kid, loginData.signing_input, exdsaAlg(loginData.key_type));
    const sigBytes  = loginData.key_type !== 'Ed25519' ? derToP1363(rawSigBytes, loginData.key_type) : rawSigBytes;
    const signature = bytesToBase64url(sigBytes);

    const confirmRes = await fetch('/authorize/confirm', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ session_id: loginData.session_id, signature }),
    });
    const confirmData = await confirmRes.json();
    if (!confirmRes.ok) {
      showError(confirmData.error_description || confirmData.error || 'Signature verification failed.');
      return;
    }

    // Save fasttrack cache for next login to this RP
    ftSave({ hsmUrl: session.hsm_url, kid, label, sub: session.selectedKey?.sub || null });
    document.getElementById('ft-row').style.display = '';
    document.getElementById('ft-key-label').textContent = label || kid;

    // Countdown 5->1 -- code issued but RP hasn't received it yet; user can still cancel
    const statusEl = document.getElementById('sign-status');
    const cancelBtn = document.getElementById('cancel-redirect-btn');
    cancelBtn.style.display = '';

    let cancelled = false;
    cancelRedirect = () => { cancelled = true; };

    let count = fasttrackActive ? 3 : 5;
    fasttrackActive = false;
    statusEl.textContent = `Redirecting in ${count}\u2026`;
    await new Promise(resolve => {
      const iv = setInterval(() => {
        count--;
        if (cancelled || count <= 0) { clearInterval(iv); resolve(); }
        else statusEl.textContent = `Redirecting in ${count}\u2026`;
      }, 1000);
    });

    cancelBtn.style.display = 'none';
    cancelRedirect = null;

    if (cancelled) {
      document.getElementById('rejected-msg').textContent =
        'Sign-in cancelled. The authorization session will expire shortly.';
      showScreen('s-rejected');
      return;
    }

    window.location.href = confirmData.redirect_url;

  } catch (err) {
    console.error('[doCompleteSign]', err);
    showError(err?.name + ': ' + (err?.message || 'unknown error'));
  }
}

// --- Cancel redirect countdown ------------------------
function doCancelRedirect() {
  if (cancelRedirect) cancelRedirect();
}

// --- Cancel -------------------------------------------
function doCancel() {
  document.getElementById('rejected-msg').textContent = 'You cancelled the login request.';
  showScreen('s-rejected');
  session = { session_id: null, signing_input: null,
    user_name: null, user_username: null, hsm_url: null, password: null,
    hem: null, listToken: null, selectedKey: null, useToken: null,
    openSearch: false, hasMobileApp: false, pendingAfterPin: null, pendingSign: null };
}

// --- Try again — full reset back to login screen ------
function doTryAgain() {
  currentOpId = null;
  mobileAbortCtrl?.abort(); mobileAbortCtrl = null;
  cancelRedirect = null;
  session = { session_id: null, signing_input: null,
    user_name: null, user_username: null, hsm_url: null, password: null,
    hem: null, listToken: null, selectedKey: null, useToken: null,
    openSearch: false, hasMobileApp: false, pendingAfterPin: null, pendingSign: null };
  document.getElementById('login-err').textContent = '';
  ftRestoreUI();
  showScreen('s-login');
}

// --- Confirm + Sign -----------------------------------
async function doConfirm() {
  const btn = document.getElementById('confirm-btn');
  btn.disabled = true;
  btn.textContent = 'Signing...';
  document.getElementById('confirm-err').textContent = '';

  document.getElementById('sign-username').textContent  = session.user_username;
  document.getElementById('sign-keysource').textContent = session.selectedKey
    ? `HSM / ${session.selectedKey.label}` : 'HSM';
  showScreen('s-signing');

  try {
    // Sign via HSM
    const sigBytes  = await session.hem.exdsaSign(
      session.useToken, session.selectedKey.kid, session.signing_input
    );
    const signature = bytesToBase64url(sigBytes);

    // POST to backend -- complete OIDC flow
    const res = await fetch('/authorize/confirm', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ session_id: session.session_id, signature }),
    });
    const data = await res.json();
    if (!res.ok) {
      showError(data.error_description || data.error || 'Signature verification failed.');
      return;
    }

    // Countdown 5->1 before redirect
    const statusEl = document.getElementById('sign-status');
    let count = 5;
    statusEl.textContent = `Redirecting in ${count}...`;
    await new Promise(resolve => {
      const iv = setInterval(() => {
        count--;
        if (count <= 0) { clearInterval(iv); resolve(); }
        else statusEl.textContent = `Redirecting in ${count}...`;
      }, 1000);
    });
    window.location.href = data.redirect_url;

  } catch (err) {
    console.error('[doConfirm]', err);
    showError(err?.name + ': ' + (err?.message || 'unknown error'));
  }
}

// --- Helpers ------------------------------------------
function hemErrMsg(err) {
  if (err instanceof HemError) {
    if (err.code === 'http_401') return 'Authentication failed. Is passphrase correct?';
    return `HSM error (${err.code}): ${err.message}`;
  }
  return `Error: ${err.message || 'Unknown error'}`;
}

function showError(msg) {
  document.getElementById('error-msg').textContent = msg;
  showScreen('s-error');
}

function bytesToBase64url(bytes) {
  let b = '';
  for (const byte of bytes) b += String.fromCharCode(byte);
  return btoa(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

// Expose to onclick handlers
window.doLogin        = doLogin;
window.doSelectKey    = doSelectKey;
window.doSubmitPin    = doSubmitPin;
window.doCancelMobile = doCancelMobile;
window.doCancel       = doCancel;
window.doTryAgain     = doTryAgain;
window.doApproveSign   = doApproveSign;
window.doCancelRedirect = doCancelRedirect;
window.doConfirm      = doConfirm;
window.showScreen     = showScreen;
