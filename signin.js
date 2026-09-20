import { HEM, jwtParse } from '/hem-sdk.js';
import { exdsaAlg, derToP1363, keyTypeDisplay, bytesToBase64url, decodeJwtHeader, decodeJwtPayload, fetchJson, hemErrMsg } from '/hsm-common.js';

// --- Test hook: broker override, localhost only -------
// The SDK talks to api.encedo.com for check-in and mobile push. The browser
// E2E test (test/e2e/sso.mjs) runs a fake device AND a fake broker; it names
// the broker with ?hem_broker=. Honoured only when the page itself is served
// from localhost, so no RP can ever point a real deployment at a broker of
// its choosing.
const HEM_OPTS = (() => {
  const isLocal = ['localhost', '127.0.0.1'].includes(location.hostname);
  const b = new URLSearchParams(location.search).get('hem_broker');
  return isLocal && b ? { broker: b } : {};
})();

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
  // SSO policy inputs from the RP -- sent along so the server can refuse a
  // reused authorization (prompt=login, max_age shorter than the session).
  prompt:                params.get('prompt')                || '',
  max_age:               params.get('max_age')               || '',
  login_hint:            params.get('login_hint')            || '',
};
// What every /authorize/login call carries. Empty optionals are left out
// (the server treats a present-but-empty max_age as a number to parse).
function oidcBody(extra = {}) {
  const b = { ...OIDC, ...extra };
  for (const k of ['prompt', 'max_age', 'login_hint', 'state', 'nonce', 'code_challenge', 'code_challenge_method']) {
    if (b[k] === '') delete b[k];
  }
  return b;
}

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
    ssoEntry:        null,   // the cached HEM session being reused (accounts screen), else null
    rememberSso:     false,  // user ticked "remember in this browser" on the confirm screen
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

// --- SSO sessions (per HEM + key) ---------------------
// A HEM token for keymgmt:use:<kid> is a bearer credential to sign with that
// key until it expires. Kept ONLY here, on the OP origin, never sent to the
// server (which must not be able to sign without the device). One entry per
// device+key; /logout (logout.js) and "Forget" remove them.
const SSO_PREFIX = 'encedo_sso:';
const ssoKey = (hsmUrl, kid) => SSO_PREFIX + hsmUrl.replace(/\/+$/, '') + '|' + kid;

function ssoList() {
  const now = Math.floor(Date.now() / 1000);
  const out = [];
  try {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
    for (const k of keys) {
      if (!k?.startsWith(SSO_PREFIX)) continue;
      let v = null;
      try { v = JSON.parse(localStorage.getItem(k)); } catch { v = null; }
      if (v?.token && v.exp > now + 30 && v.hsm_url && v.kid) out.push({ key: k, ...v });
      else localStorage.removeItem(k);          // expired or malformed
    }
  } catch { /* storage unavailable */ }
  return out.sort((a, b) => (b.iat ?? 0) - (a.iat ?? 0));
}
function ssoSave(entry)   { try { localStorage.setItem(ssoKey(entry.hsm_url, entry.kid), JSON.stringify(entry)); } catch {} }
function ssoForget(key)   { try { localStorage.removeItem(key); } catch {} }
function ssoForgetAll()   { for (const e of ssoList()) ssoForget(e.key); }

const SSO_REJECT_TEXT = {
  client:   'This application requires confirmation on your HEM at every sign-in.',
  user:     'Your account requires confirmation on your HEM at every sign-in.',
  prompt:   'The application asked for a fresh sign-in.',
  max_age:  'The application requires a more recent sign-in.',
  too_old:  'Your browser session is too old for single sign-on.',
  disabled: 'Single sign-on is disabled on this server.',
};

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
    document.getElementById('rp-label-accounts').textContent = rpHost;
  } catch {
    const label = OIDC.client_id || 'Unknown client';
    document.getElementById('rp-label-login').textContent = label;
    document.getElementById('rp-label-accounts').textContent = label;
  }

  lsRestoreHints();
  ftRestoreUI();
  maybeShowAccounts();

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

// --- SSO: accounts screen -----------------------------
// With a usable session in this browser the page opens on the account list
// instead of the HSM URL form. prompt=login from the RP skips it (the server
// would refuse the session anyway; no point offering it).
function maybeShowAccounts() {
  if ((OIDC.prompt || '').split(' ').includes('login')) return false;
  const list = ssoList();
  if (!list.length) return false;
  renderAccounts(list);
  showScreen('s-accounts');
  return true;
}

function renderAccounts(list) {
  const box = document.getElementById('acct-list');
  box.replaceChildren();
  const hint = (OIDC.login_hint || '').toLowerCase();
  const ordered = hint
    ? [...list].sort((a, b) => Number((b.username || '').toLowerCase() === hint) - Number((a.username || '').toLowerCase() === hint))
    : list;
  for (const e of ordered) {
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'acct';
    btn.dataset.action = 'sso-pick'; btn.dataset.key = e.key;
    const dot = document.createElement('span'); dot.className = 'acct-dot';
    const txt = document.createElement('span');
    const name = document.createElement('div'); name.className = 'acct-name'; name.textContent = e.username || e.sub;
    const meta = document.createElement('div'); meta.className = 'acct-meta';
    let host = e.hsm_url; try { host = new URL(e.hsm_url).host; } catch { /* keep */ }
    const until = new Date(e.exp * 1000);
    meta.textContent = `HEM ${host} · ${e.label || e.kid.slice(0, 8)} · session until ${until.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    txt.append(name, meta);
    btn.append(dot, txt);
    box.appendChild(btn);
  }
}

// One click: prove the device is there, ask the server to reuse the
// authorization, sign with the cached token. Anything the server or the
// device refuses turns into the ordinary confirm-and-authorize path.
async function doSsoPick(key) {
  const entry = ssoList().find(e => e.key === key);
  if (!entry) { maybeShowAccounts() || showScreen('s-login'); return; }
  const errEl = document.getElementById('acct-err');
  const btns  = [...document.querySelectorAll('#acct-list .acct')];
  if (btns.some(b => b.disabled)) return;
  errEl.textContent = '';
  btns.forEach(b => { b.disabled = true; });

  try {
    session = freshSession();
    session.hsm_url     = entry.hsm_url;
    session.hem         = new HEM(entry.hsm_url, HEM_OPTS);
    session.ssoEntry    = entry;
    session.selectedKey = { kid: entry.kid, label: entry.label || '', sub: entry.sub };
    session.keys        = [{ kid: entry.kid, label: entry.label || '' }];
    lsSaveHints(entry.hsm_url);

    try {
      await session.hem.getVersion({ timeoutMs: 4000 });
    } catch {
      throw Object.assign(new Error('Your HEM is not reachable. Plug it in or check that it is online, then try again.'), { code: 'hem_unreachable' });
    }

    const loginData = await fetchJson('/authorize/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(oidcBody({ sub: entry.sub, sso_iat: String(entry.iat) })),
    });
    const { kid } = entry; const label = entry.label || '';
    // The server pins the registered key; a stale entry (re-enrolled key) is useless.
    const expectedKid = decodeJwtHeader(loginData.signing_input)?.kid;
    if (expectedKid && expectedKid !== kid) {
      ssoForget(entry.key);
      throw new Error('This session belongs to a key that is no longer registered. Sign in with your HEM.');
    }

    if (loginData.sso?.used) {
      session.pendingSign = { kid, label, loginData };
      await doCompleteSign(entry.token, kid, label, loginData);
      return;
    }
    // Refused by policy: fresh authorization, with the reason on the confirm screen.
    session.ssoEntry = null;
    showConfirm(loginData, kid, label, SSO_REJECT_TEXT[loginData.sso?.rejected] || 'Confirmation on your HEM is required.');
  } catch (e) {
    errEl.textContent = e.code === 'hem_unreachable' ? e.message : (e.status ? e.message : hemErrMsg(e));
    btns.forEach(b => { b.disabled = false; });
  }
}

// Populate and show the confirm screen for a /authorize/login response.
function showConfirm(loginData, kid, label, note = null) {
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

  const noteEl = document.getElementById('tc-note');
  noteEl.textContent = note || '';
  noteEl.style.display = note ? '' : 'none';
  // "Remember" only when client and user policy allow caching this authorization.
  const canSso = !!loginData.sso?.enabled;
  document.getElementById('tc-remember-row').style.display = canSso ? '' : 'none';
  document.getElementById('tc-remember-hours').textContent = String(Math.max(1, Math.round((loginData.sso?.suggest_seconds ?? 28800) / 3600)));

  session.pendingSign = { kid, label, loginData };
  showScreen('s-token-confirm');
}

// The lifetime to ask the HEM for: the server's suggestion when this
// authorization is going to be kept for SSO, else the SDK's short default.
function authorizeLifetime(loginData) {
  return session.rememberSso && loginData?.sso?.enabled ? loginData.sso.suggest_seconds : 300;
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

    const hem = new HEM(hsmUrl, HEM_OPTS);
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
      body:    JSON.stringify(oidcBody({ sub })),
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
      const useToken = await session.hem.authorizePassword(pin, scope, authorizeLifetime(loginData));
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
      body:    JSON.stringify(oidcBody({ sub })),
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

    btn.disabled = false;
    btn.textContent = 'Next \u2192';
    showConfirm(loginData, kid, label);

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
  session.rememberSso = !!(document.getElementById('tc-remember')?.checked && loginData?.sso?.enabled);
  const expSeconds = authorizeLifetime(loginData);

  try {
    let useToken;

    if (session.password) {
      useToken = await session.hem.authorizePassword(session.password, scope, expSeconds);
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
        expSeconds,
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
    let rawSigBytes;
    try {
      rawSigBytes = await session.hem.exdsaSign(useToken, kid, loginData.signing_input, exdsaAlg(loginData.key_type));
    } catch (e) {
      // A cached SSO token the device no longer accepts (expired, device
      // rebooted or unplugged, token revoked): drop it and start a fresh,
      // interactive sign-in for the same key.
      if (session.ssoEntry && (e?.code === 'http_401' || e?.code === 'http_403')) {
        ssoForget(session.ssoEntry.key);
        session.ssoEntry = null;
        const fresh = await fetchJson('/authorize/login', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(oidcBody({ sub: session.selectedKey?.sub })),
        });
        showConfirm(fresh, kid, label, 'Your HEM session has ended. Confirm this sign-in on your HEM.');
        return;
      }
      throw e;
    }
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

    // Keep this authorization for SSO when the user asked and policy allows.
    // exp/iat come from the HEM token itself: the device (or the user on the
    // phone) decides the lifetime, not the page.
    if (session.rememberSso && !session.ssoEntry && loginData.sso?.enabled) {
      const now = Math.floor(Date.now() / 1000);
      const tp  = jwtParse(useToken) || {};
      ssoSave({
        token: useToken,
        iat: Number.isFinite(tp.iat) ? tp.iat : now,
        exp: Number.isFinite(tp.exp) ? tp.exp : now + (loginData.sso.suggest_seconds || 300),
        sub: session.selectedKey?.sub || decodeJwtPayload(loginData.signing_input)?.sub || null,
        username: loginData.user_username || '',
        label, kid, hsm_url: session.hsm_url, key_type: loginData.key_type,
      });
    }

    // Countdown 5->1 -- code issued but RP hasn't received it yet; user can still cancel
    const statusEl = document.getElementById('sign-status');
    const cancelBtn = document.getElementById('cancel-redirect-btn');
    cancelBtn.style.display = '';

    let cancelled = false;
    cancelRedirect = () => { cancelled = true; };

    let count = (fasttrackActive || session.ssoEntry) ? 3 : 5;
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
  if (!maybeShowAccounts()) showScreen('s-login');
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
  'sso-pick':           el => doSsoPick(el.dataset.key),
  'sso-forget-all':     () => { ssoForgetAll(); showScreen('s-login'); },
};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  const fn = el && ACTIONS[el.dataset.action];
  if (fn) { e.preventDefault(); fn(el); }
});
