import { HEM } from '/hem-sdk.js';
import { exdsaAlg, derToP1363, keyTypeDisplay, bytesToBase64url, decodeJwtHeader, decodeJwtPayload, fetchJson, hemErrMsg } from '/hsm-common.js';

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

// The device pages its search at 15 entries by default; ask for more so a
// second account or a re-enrolled key on the same HSM is never silently cut off.
const KEY_LIST_LIMIT = 100;

// --- Session (in-memory only) -------------------------
function freshSession() {
  return {
    session_id:      null,
    hsm_url:         null,
    password:        null,
    hem:             null,   // HEM instance
    listToken:       null,   // keymgmt:search token
    selectedKey:     null,   // { kid, label, sub }
    openSearch:      false,  // HSM allows unauthenticated search
    hasMobileApp:    false,  // HSM has mobile-app keys (description 'EXTAID…')
    keys:            [],     // last key list from searchKeys -- to re-pick by kid
    pendingAfterPin: null,   // 'search' | 'use'
    pendingSign:     null,   // { useToken, kid, label, loginData } -- set before s-token-confirm
  };
}
let session = freshSession();

// Used to cancel stale async mobile-auth operations
let currentOpId = null;
let mobileAbortCtrl = null;
let fasttrackActive = false;

// --- localStorage helpers -----------------------------
// The stored value is rendered as a DOM node, never as markup.
function setDatalist(dl, value) {
  const o = document.createElement('option');
  o.value = value;
  dl.replaceChildren(o);
}
const LS_HSM_URL  = 'encedo_oidc_hsm_url';

function lsSaveHints(hsmUrl) {
  try {
    if (hsmUrl) localStorage.setItem(LS_HSM_URL, hsmUrl);
    const dl    = document.getElementById('hsm-url-list');
    const saved = localStorage.getItem(LS_HSM_URL);
    if (saved && dl) setDatalist(dl, saved);
  } catch {}
}

function lsRestoreHints() {
  try {
    const h = localStorage.getItem(LS_HSM_URL);
    if (h) {
      document.getElementById('hsm-url-input').value = h;
      const dl = document.getElementById('hsm-url-list');
      if (dl) setDatalist(dl, h);
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
    document.getElementById('sign-audience').textContent  = rpHost;
  } catch {
    const label = OIDC.client_id || 'Unknown client';
    document.getElementById('rp-label-login').textContent = label;
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
  // Leaving the passphrase screen ("Back") must not leave the passphrase in the input.
  if (id !== 's-pin') document.getElementById('pin-input').value = '';
}

// --- Step 1: Login -> HSM checkin -> detect capabilities -> search keys -----
async function doLogin() {
  const btn = document.getElementById('login-btn');
  if (btn.disabled) return;   // Enter while a login is in flight -- one run at a time
  const hsmUrl = document.getElementById('hsm-url-input').value.trim();
  if (!hsmUrl) {
    document.getElementById('login-err').textContent = 'Please enter the HSM URL.';
    return;
  }

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

    // Step A: detect mobile-app support (keys described 'EXTAID…'; the SDK anchors and base64-encodes the pattern)
    btn.textContent = 'Detecting HSM capabilities...';
    try {
      const mobileKeys = await hem.searchKeys(null, 'EXTAID', 0, 1);
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
      const keys = await hem.searchKeys(null, 'ETSOIDC', 0, KEY_LIST_LIMIT);
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
    const loginData = await fetchJson('/authorize/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ sub, ...OIDC }),
    });
    // The server pins the registered key in the JWT header. A cached kid from
    // before a re-enrollment would sign with the wrong key and fail at
    // /authorize/confirm every time; detect it here and fall back to the list.
    const expectedKid = decodeJwtHeader(loginData.signing_input)?.kid;
    if (expectedKid && expectedKid !== kid) throw new Error(`cached key ${kid} is no longer the registered key (${expectedKid})`);

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
  const btn = document.getElementById('pin-btn');
  if (btn.disabled) return;   // second Enter while authorizing
  const pin = document.getElementById('pin-input').value;
  if (!pin) {
    document.getElementById('pin-err').textContent = 'Please enter your passphrase.';
    return;
  }

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
      const keys = await session.hem.searchKeys(listToken, 'ETSOIDC', 0, KEY_LIST_LIMIT);
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
  session.keys = keys;

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

  // property, not addEventListener: the list is re-rendered on retry and
  // listeners would stack up
  sel.onchange = () => {
    const opt = sel.selectedOptions[0];
    session.selectedKey = { kid: opt.value, label: opt.dataset.label, sub: opt.dataset.sub || null };
  };
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
  if (btn.disabled) return;
  btn.disabled = true;
  btn.textContent = 'Loading\u2026';
  document.getElementById('keys-err').textContent = '';

  let { kid, label } = session.selectedKey;

  try {
    const sub = session.selectedKey?.sub || null;
    const loginData = await fetchJson('/authorize/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ sub, ...OIDC }),
    });

    // The JWT header names the key registered for this account. Several keys
    // can carry the same ETSOIDC<sub> description (each failed enrollment
    // attempt leaves one behind); if the user picked a clone, switch to the
    // registered one when it is on the device, otherwise say so instead of
    // producing a signature the server will reject.
    const expectedKid = decodeJwtHeader(loginData.signing_input)?.kid;
    if (expectedKid && expectedKid !== kid) {
      const registered = session.keys.find(k => k.kid === expectedKid);
      if (!registered) {
        throw new Error(`The selected key is not the one registered for this account (expected ${expectedKid.slice(0, 8)}…). Re-enroll or pick another account.`);
      }
      console.warn(`[signin] key ${kid} is a clone; using registered key ${expectedKid}`);
      kid = registered.kid; label = registered.label || '';
      session.selectedKey = { kid, label, sub };
    }

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
  mobileAbortCtrl?.abort(); mobileAbortCtrl = null; // stop broker polling (the SDK withdraws the broker event on abort)
  document.getElementById('cancel-mobile-btn').style.display = 'none';
  if (session.password) {
    doApproveSign(); // retry with cached passphrase
  } else {
    session.pendingAfterPin = 'approve';
    showPinScreen();
  }
}

function fmtTs(unixSec) {
  return new Date(unixSec * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

// --- Step 3: Approve -> authorize HSM key --------------
async function doApproveSign() {
  const btn = document.getElementById('tc-approve-btn');
  if (btn.disabled) return;
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

    let confirmData;
    try {
      confirmData = await fetchJson('/authorize/confirm', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ session_id: loginData.session_id, signature }),
      });
    } catch (e) {
      // Whatever the reason, the cached fast-track key did not produce an
      // acceptable signature -- forget it so the next attempt goes through the
      // key list instead of failing the same way again.
      ftClear();
      document.getElementById('ft-row').style.display = 'none';
      showError(e.status ? e.message : hemErrMsg(e));
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
    showError(hemErrMsg(err));
  } finally {
    // The signature is made (or not); nothing after this needs the passphrase
    // or the X25519 keys the SDK derived from it. Drop both.
    session.password = null;
    try { session.hem?.clearKeys(); } catch { /* SDK without clearKeys */ }
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
  session = freshSession();
}

// --- Try again — full reset back to login screen ------
function doTryAgain() {
  currentOpId = null;
  mobileAbortCtrl?.abort(); mobileAbortCtrl = null;
  cancelRedirect = null;
  session = freshSession();
  document.getElementById('login-err').textContent = '';
  ftRestoreUI();
  showScreen('s-login');
}


function showError(msg) {
  document.getElementById('error-msg').textContent = msg;
  showScreen('s-error');
}

// Click dispatch -- buttons carry data-action, no inline handlers (CSP has no
// script-src-attr, so on*= attributes would be blocked anyway).
const ACTIONS = {
  'do-login':           () => doLogin(),
  'do-select-key':      () => doSelectKey(),
  'do-submit-pin':      () => doSubmitPin(),
  'do-cancel-mobile':   () => doCancelMobile(),
  'do-cancel':          () => doCancel(),
  'do-try-again':       () => doTryAgain(),
  'do-approve-sign':    () => doApproveSign(),
  'do-cancel-redirect': () => doCancelRedirect(),
  'show-screen':        el => showScreen(el.dataset.screen),
};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  const fn = el && ACTIONS[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el); }
});
