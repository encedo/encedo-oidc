/* -- scope / pkce helpers -- */
function togglePkce(id) {
  document.getElementById(id).classList.toggle('on');
}

function getScopesFrom(containerId) {
  return [...document.querySelectorAll(`#${containerId} .scope-tag.on`)]
    .map(el => el.dataset.scope);
}

function setScopesIn(containerId, active) {
  document.querySelectorAll(`#${containerId} .scope-tag`).forEach(el => {
    el.classList.toggle('on', active.includes(el.dataset.scope));
  });
}

function initScopeTags(containerId) {
  document.querySelectorAll(`#${containerId} .scope-tag`).forEach(el => {
    el.onclick = () => {
      if (el.dataset.scope === 'openid') return; // always required
      el.classList.toggle('on');
    };
  });
}

/* -- state -- */
let _usersCache = [];
let _clientsCache = [];
let _editClientId = null;
let _rotateId = null;

/* -- helpers -- */
const $ = id => document.getElementById(id);
let _healthTimer = null;
const checkHealthDebounced = () => { clearTimeout(_healthTimer); _healthTimer = setTimeout(checkHealth, 600); };
const base = () => $('api-base').value.replace(/\/$/, '');
const secret = () => $('api-secret').value;
const hdrs = () => ({'Content-Type':'application/json','Authorization':`Bearer ${secret()}`});
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

async function api(path, opts = {}) {
  const res = await fetch(base() + path, {
    ...opts,
    headers: {...hdrs(), ...(opts.headers || {})},
  });
  const body = res.status === 204 ? null : await res.json();
  if (!res.ok) throw new Error(body?.detail || body?.error || `HTTP ${res.status}`);
  return body;
}

function fmt(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, {day:'2-digit',month:'2-digit',year:'numeric'})
       + ' ' + d.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit'});
}

function toast(msg, type = 'ok') {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type==='ok'?'[ok]':'[x]'}</span><span>${msg}</span>`;
  $('toasts').appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function copyText(id) {
  navigator.clipboard.writeText($(id).textContent);
  toast('Copied to clipboard');
}

function toggleTheme() {
  const light = document.documentElement.classList.toggle('light');
  // theme label updated below
  $('theme-label').textContent = light ? 'Dark' : 'Light';
}

function showPage(name, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.admin-nav-item').forEach(b => b.classList.remove('active'));
  $('page-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'users')   loadUsers();
  if (name === 'clients') loadClients();
  if (name === 'audit')   loadAudit(true);
  if (name === 'invites') loadInvites();
}

function openModal(id)  { $(id).classList.add('open'); }
function closeModal(id) { $(id).classList.remove('open'); }

document.addEventListener('keydown', e => {
  if (e.key === 'Escape')
    document.querySelectorAll('.overlay.open').forEach(o => o.classList.remove('open'));
});
document.querySelectorAll('.overlay').forEach(o => {
  o.addEventListener('click', e => { if (e.target === o) o.classList.remove('open'); });
});

/* -- health -- */
async function checkHealth() {
  const dot = $('status-dot'), txt = $('status-text');
  try {
    const r = await fetch(base() + '/health');
    if (!r.ok) throw 0;
    const health = await r.json();
    if (health.commit) $('version-label').textContent = ' v ' + health.commit;
    // URL reachable — check if secret is valid by probing admin endpoint
    const r2 = await fetch(base() + '/admin/users', {
      method: 'HEAD',
      headers: { Authorization: 'Bearer ' + secret() }
    });
    if (r2.ok || r2.status === 405) {
      // 200 or 405 (Method Not Allowed) = auth passed
      dot.className = 'status-dot'; dot.style.background = '';
      txt.textContent = new URL(base()).host;
      loadUsers();
    } else {
      // 401/403 = URL ok but secret wrong
      dot.className = 'status-dot'; dot.style.background = 'var(--amber)';
      txt.textContent = new URL(base()).host + ' — bad secret';
    }
  } catch { dot.className = 'status-dot red'; dot.style.background = ''; txt.textContent = 'unreachable'; }
}

/* ==================== USERS ==================== */

async function loadUsers() {
  const b = $('users-body');
  b.innerHTML = '<div class="loading-row"><span class="spinner"></span></div>';
  try {
    const users = await api('/admin/users');
    _usersCache = users;
    $('users-sub').textContent = users.length + ' registered user' + (users.length !== 1 ? 's' : '');
    if (!users.length) {
      b.innerHTML = '<div class="empty">No users yet</div>';
      return;
    }
    b.innerHTML = users.map((u, i) => `
      <div class="table-row" style="grid-template-columns:1fr 1.3fr 1.6fr 1fr 1fr 1fr;">
        <div class="cell-name">${esc(u.username || u.sub)}</div>
        <div class="cell-mono" style="color:var(--text)">${esc(u.name || '-')}</div>
        <div class="cell-mono">${esc(u.email || '-')}</div>
        <div class="cell-mono" style="font-size:10px">${esc(u.hsm_url)}</div>
        <div class="cell-muted">${fmt(u.created_at)}</div>
        <div class="cell-actions">
          <button class="btn btn-xs" style="background:rgba(52,216,154,.12);border:1px solid rgba(52,216,154,.3);color:var(--green)" onclick="requestEnrollment('${esc(u.sub)}', ${!!u.pubkey})">${u.pubkey ? 'Renew' : 'New Enrollment'}</button>
          <button class="btn btn-ghost btn-xs" onclick="openEditUser(${i})">Edit</button>
          <button class="btn btn-danger btn-xs" onclick="delUser('${esc(u.sub)}','${esc(u.username)}')">Delete</button>
        </div>
      </div>`).join('');
  } catch (e) {
    b.innerHTML = `<div style="padding:16px 20px;font-family:var(--mono);font-size:11px;color:var(--red)">${e.message}</div>`;
  }
}

/* ADD */
function openAddUser() {
  ['u-username','u-firstname','u-lastname','u-email'].forEach(id => $(id).value = '');
  $('u-hsm').value = 'https://my.ence.do';
  openModal('modal-add-user');
  setTimeout(() => $('u-username').focus(), 60);
}

async function submitAddUser() {
  const username  = $('u-username').value.trim();
  const firstname = $('u-firstname').value.trim();
  const lastname  = $('u-lastname').value.trim();
  const name      = [firstname, lastname].filter(Boolean).join(' ');
  const email     = $('u-email').value.trim();
  const hsm_url   = $('u-hsm').value.trim();

  if (!username)  return toast('Username required', 'err');
  if (!firstname) return toast('First name required', 'err');
  if (!lastname)  return toast('Last name required', 'err');
  if (!email)     return toast('Email required', 'err');
  if (!hsm_url)   return toast('HSM URL required', 'err');

  try {
    const user = await api('/admin/users', {method:'POST', body:JSON.stringify({username, name, email, hsm_url})});
    closeModal('modal-add-user');

    const { enrollment_url } = user;

    $('nu-username').textContent   = user.username;
    $('nu-sub').textContent        = user.sub;
    $('nu-enroll-url').textContent = enrollment_url;
    openModal('modal-user-created');

    loadUsers();
  } catch (e) { toast(e.message, 'err'); }
}

/* EDIT */
async function openEditUser(idx) {
  const u = _usersCache[idx];
  const parts = (u.name || '').split(' ');
  $('eu-sub').textContent       = u.sub;
  $('eu-username').value        = u.username || '';
  $('eu-firstname').value       = parts[0] || '';
  $('eu-lastname').value        = parts.slice(1).join(' ') || '';
  $('eu-email').value           = u.email || '';
  $('eu-hsm').value             = u.hsm_url || '';
  $('eu-kid').textContent       = u.kid || '--';
  $('eu-key-type').textContent  = u.key_type || 'EdDSA';
  $('eu-pubkey-preview').textContent = u.pubkey
    ? btoa(u.pubkey.match(/../g).map(h=>String.fromCharCode(parseInt(h,16))).join(''))
    : '--';
  openModal('modal-edit-user');
  setTimeout(() => $('eu-username').focus(), 60);
  await _renderClientsChecklist(u.clients || []);
  // load claims
  try {
    const claims = await api(`/admin/users/${u.sub}/claims`);
    $('eu-hsm-url-toggle').checked = claims.hsm_url_in_userinfo;
    _renderClaimRows(claims.custom_claims);
  } catch { _renderClaimRows({}); }
}

function _renderClaimRows(claims) {
  const list = $('eu-claims-list');
  list.innerHTML = '';
  for (const [k, v] of Object.entries(claims)) _addClaimRow(k, v);
}

function _addClaimRow(k = '', v = '') {
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center;';
  row.innerHTML = `
    <input class="field-input claim-key" placeholder="claim_key" value="${esc(k)}"
      style="width:160px;padding:7px 10px;font-size:12px;font-family:var(--mono);">
    <input class="field-input claim-val" placeholder="value" value="${esc(v)}"
      style="flex:1;padding:7px 10px;font-size:12px;font-family:var(--mono);">
    <button class="btn btn-danger btn-xs" onclick="this.parentElement.remove()" style="flex-shrink:0">&#215;</button>`;
  $('eu-claims-list').appendChild(row);
}

function addClaimRow() { _addClaimRow(); }

function _getClaimsFromUI() {
  const result = {};
  for (const row of $('eu-claims-list').children) {
    const k = row.querySelector('.claim-key').value.trim();
    const v = row.querySelector('.claim-val').value;
    if (k) result[k] = v;
  }
  return result;
}

async function _renderClientsChecklist(selectedIds) {
  const wrap = $('eu-clients-list');
  wrap.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--muted);padding:10px 0">loading...</div>';
  try {
    _clientsCache = await api('/admin/clients');
    if (!_clientsCache.length) {
      wrap.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--muted);padding:10px 0">No clients defined yet</div>';
      return;
    }
    wrap.innerHTML = _clientsCache.map(c => `
      <label class="client-check">
        <input type="checkbox" data-cid="${esc(c.client_id)}" ${selectedIds.includes(c.client_id) ? 'checked' : ''}>
        <span class="client-check-name">${esc(c.name)}</span>
        <span class="client-check-id">${esc(c.client_id)}</span>
      </label>`).join('');
  } catch (e) {
    wrap.innerHTML = `<div style="font-family:var(--mono);font-size:10px;color:var(--red);padding:10px 0">${e.message}</div>`;
  }
}

async function submitEditUser() {
  const sub       = $('eu-sub').textContent.trim();
  const firstname = $('eu-firstname').value.trim();
  const lastname  = $('eu-lastname').value.trim();
  const updates = {
    username : $('eu-username').value.trim(),
    name     : [firstname, lastname].filter(Boolean).join(' '),
    email    : $('eu-email').value.trim(),
    hsm_url  : $('eu-hsm').value.trim(),
    clients  : [...document.querySelectorAll('#eu-clients-list input:checked')].map(el => el.dataset.cid),
  };
  if (!updates.username) return toast('Username required', 'err');
  if (!updates.hsm_url)  return toast('HSM URL required', 'err');
  try {
    await api(`/admin/users/${sub}`, {method:'PATCH', body:JSON.stringify(updates)});
    await api(`/admin/users/${sub}/claims`, {method:'PUT', body:JSON.stringify({
      custom_claims:       _getClaimsFromUI(),
      hsm_url_in_userinfo: $('eu-hsm-url-toggle').checked,
    })});
    closeModal('modal-edit-user');
    toast('User updated');
    loadUsers();
  } catch (e) { toast(e.message, 'err'); }
}

async function requestEnrollment(sub, hasKey) {
  if (hasKey) {
    const ok = confirm('This user already has an enrolled key.\nGenerating a new enrollment link will overwrite the existing key when completed.\n\nContinue?');
    if (!ok) return;
  }
  try {
    const data = await api(`/admin/users/${encodeURIComponent(sub)}/enrollment`, { method: 'POST' });
    document.getElementById('enroll-url').textContent = data.enrollment_url;
    openModal('modal-enrollment');
  } catch (e) { toast(e.message, 'err'); }
}

async function openInviteUser() {
  ['inv-username','inv-name','inv-email'].forEach(id => $(id).value = '');
  const sel = $('inv-client');
  sel.innerHTML = '<option value="">loading...</option>';
  openModal('modal-invite-user');
  try {
    const clients = await api('/admin/clients');
    if (!clients.length) {
      sel.innerHTML = '<option value="">No clients defined</option>';
      return;
    }
    sel.innerHTML = clients.map(c =>
      `<option value="${esc(c.client_id)}">${esc(c.name)}</option>`
    ).join('');
  } catch (e) {
    sel.innerHTML = `<option value="">Error: ${esc(e.message)}</option>`;
  }
}

async function submitInviteUser() {
  const client_id = $('inv-client').value;
  if (!client_id) return toast('Select a client', 'err');
  const body = { client_id };
  const username = $('inv-username').value.trim();
  const name     = $('inv-name').value.trim();
  const email    = $('inv-email').value.trim();
  if (username) body.username = username;
  if (name)     body.name     = name;
  if (email)    body.email    = email;
  try {
    const data = await api('/admin/invite', { method: 'POST', body: JSON.stringify(body) });
    closeModal('modal-invite-user');
    $('inv-result-url').textContent = data.invite_url;
    openModal('modal-invite-link');
  } catch (e) { toast(e.message, 'err'); }
}

async function delUser(sub, username) {
  if (!confirm(`Delete user "${username || sub}"?`)) return;
  try {
    await api(`/admin/users/${sub}`, {method:'DELETE'});
    toast(`User "${username || sub}" deleted`);
    loadUsers();
  } catch (e) { toast(e.message, 'err'); }
}

/* ==================== AUDIT LOG ==================== */

let _auditPage  = [];   // current page entries (raw from server)
let _auditOffset = 0;
let _auditLimit  = 20;
let _auditTotal  = 0;

const AUDIT_DOT_COLOR = {
  'auth.login.ok':     'var(--green)',
  'auth.signature.ok': 'var(--green)',
  'auth.token.issued': 'var(--green)',
};
function auditColor(type) {
  if (AUDIT_DOT_COLOR[type])          return AUDIT_DOT_COLOR[type];
  if (type.startsWith('auth.'))       return 'var(--red)';
  if (type.startsWith('admin.'))      return 'var(--amber)';
  if (type.startsWith('enrollment.')) return 'var(--lavender)';
  if (type.startsWith('ratelimit.'))  return 'var(--amber)';
  return 'var(--soft)';
}

function fmtMs(ms) {
  const d = new Date(ms);
  return d.toLocaleDateString(undefined, {day:'2-digit',month:'2-digit',year:'numeric'})
       + ' ' + d.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function fmtIp(ip) {
  if (!ip) return '--';
  return ip.replace(/^::ffff:/, '');  // display IPv4-mapped as plain IPv4
}

async function loadAudit(reset = false) {
  if (reset) _auditOffset = 0;
  $('audit-body').innerHTML = '<div class="loading-row"><span class="spinner"></span></div>';
  try {
    const data = await api(`/admin/audit-log?limit=${_auditLimit}&offset=${_auditOffset}`);
    _auditPage  = data.entries;
    _auditTotal = data.total;
    const pageNum  = Math.floor(_auditOffset / _auditLimit) + 1;
    const pageCount = Math.max(1, Math.ceil(_auditTotal / _auditLimit));
    $('audit-sub').textContent       = `${_auditTotal} event${_auditTotal !== 1 ? 's' : ''} total`;
    $('audit-page-info').textContent = `Page ${pageNum} of ${pageCount}`;
    const atStart = _auditOffset === 0;
    const atEnd   = _auditOffset + _auditLimit >= _auditTotal;
    function setNavBtn(id, disabled) {
      const b = $(id);
      b.disabled       = disabled;
      b.style.opacity  = disabled ? '0.25' : '1';
      b.style.cursor   = disabled ? 'not-allowed' : 'pointer';
    }
    setNavBtn('audit-prev-btn', atStart);
    setNavBtn('audit-next-btn', atEnd);
    applyAuditFilter();
  } catch (e) {
    $('audit-body').innerHTML =
      `<div style="padding:16px 20px;font-family:var(--mono);font-size:11px;color:var(--red)">${esc(e.message)}</div>`;
  }
}

function auditPrevPage() {
  if (_auditOffset === 0) return;
  _auditOffset = Math.max(0, _auditOffset - _auditLimit);
  loadAudit(false);
}

function auditNextPage() {
  if (_auditOffset + _auditLimit >= _auditTotal) return;
  _auditOffset += _auditLimit;
  loadAudit(false);
}

function auditChangeLimit() {
  _auditLimit  = parseInt($('audit-limit').value, 10);
  _auditOffset = 0;
  loadAudit(false);
}

function applyAuditFilter() {
  const prefix   = $('audit-filter').value;
  const filtered = prefix ? _auditPage.filter(e => e.type.startsWith(prefix)) : _auditPage;
  renderAuditEntries(filtered);
}

function renderAuditEntries(entries) {
  const b    = $('audit-body');
  const COLS = '150px 210px 1fr 130px 36px';
  if (!entries.length) {
    b.innerHTML = '<div class="empty">No events</div>';
    return;
  }
  b.innerHTML = entries.map((e, i) => {
    const color = auditColor(e.type);
    const user  = e.username && e.sub
      ? `<span style="color:var(--text)">${esc(e.username)}</span><br><span style="color:var(--muted);font-size:9px;">${esc(e.sub)}</span>`
      : e.username ? esc(e.username)
      : e.sub      ? `<span style="font-size:9px;">${esc(e.sub)}</span>`
      : '--';
    const ip    = esc(fmtIp(e.ip));
    const extra = Object.entries(e)
      .filter(([k]) => !['ts','type','sub','username','ip'].includes(k))
      .map(([k,v]) => `<span class="info-key">${esc(k)}</span>&nbsp;<span class="info-value">${esc(Array.isArray(v) ? v.join(', ') : String(v))}</span>`)
      .join(' &nbsp;&middot;&nbsp; ');
    return `
      <div class="table-row" style="grid-template-columns:${COLS};cursor:pointer;" onclick="toggleAuditRow(${i})">
        <div class="cell-mono" style="font-size:10px;color:var(--muted)">${fmtMs(e.ts)}</div>
        <div class="cell-mono" style="display:flex;align-items:center;gap:7px;">
          <span style="width:6px;height:6px;border-radius:50%;background:${color};flex-shrink:0;display:inline-block;"></span>
          ${esc(e.type)}
        </div>
        <div class="cell-mono">${user}</div>
        <div class="cell-mono" style="color:var(--muted)">${ip}</div>
        <div style="display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:9px;" id="audit-ch-${i}">></div>
      </div>
      <div id="audit-det-${i}" style="display:none;padding:7px 20px 9px;font-family:var(--mono);font-size:10px;color:var(--soft);border-bottom:1px solid var(--rim);background:rgba(0,0,0,.18);">
        <span class="info-key">ts</span>&nbsp;<span class="info-value">${e.ts}</span>
        ${e.sub ? ` &nbsp;&middot;&nbsp; <span class="info-key">sub</span>&nbsp;<span class="info-value">${esc(e.sub)}</span>` : ''}
        ${extra ? ' &nbsp;&middot;&nbsp; ' + extra : ''}
      </div>`;
  }).join('');
}

function toggleAuditRow(i) {
  const det  = $(`audit-det-${i}`);
  const ch   = $(`audit-ch-${i}`);
  const open = det.style.display !== 'none';
  det.style.display = open ? 'none' : 'block';
  ch.textContent    = open ? '>' : 'v';
}

/* ==================== CLIENTS ==================== */

async function loadClients() {
  const b = $('clients-body');
  b.innerHTML = '<div class="loading-row"><span class="spinner"></span></div>';
  try {
    const cls = await api('/admin/clients');
    _clientsCache = cls;
    $('clients-sub').textContent = cls.length + ' relying part' + (cls.length !== 1 ? 'ies' : 'y');
    $('jwks-panel').style.display = cls.length ? 'block' : 'none';
    $('jwks-url').textContent = base() + '/jwks.json';
    if (!cls.length) {
      b.innerHTML = '<div class="empty">No clients yet</div>';
      return;
    }
    b.innerHTML = cls.map((c,ci) => {
      const urimeta = (c.redirect_uris || []).map(u => u.replace(/^https?:\/\//, '')).join(' - ');
      const scopePills = (c.scopes || ['openid']).map(s =>
        `<span class="scope-pill">${esc(s)}</span>`).join('');
      return `<div class="client-card">
        <div class="client-card-body">
          <div class="client-card-name">${esc(c.name)}</div>
          <div class="client-card-meta">id: <span>${esc(c.client_id)}</span> &nbsp;&middot;&nbsp; ${esc(urimeta)}</div>
          <div class="client-card-scopes">${scopePills}</div>
        </div>
        <div class="client-card-actions">
          <button class="btn btn-ghost btn-xs" onclick="openEditClient(${ci})">Edit</button>
          <button class="btn btn-danger btn-xs" onclick="delClient('${esc(c.client_id)}','${esc(c.name)}')">Delete</button>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    b.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--red);padding:16px">${e.message}</div>`;
  }
}

function openAddClient() {
  $('c-name').value = ''; $('c-uris').value = '';
  $('c-id-ttl').value = 3600; $('c-at-ttl').value = 3600;
  setScopesIn('c-scopes', ['openid','profile','email']);
  $('c-pkce').classList.add('on');
  initScopeTags('c-scopes');
  openModal('modal-add-client');
  setTimeout(() => $('c-name').focus(), 60);
}

async function submitAddClient() {
  const name   = $('c-name').value.trim();
  const uris   = $('c-uris').value.split('\n').map(s => s.trim()).filter(Boolean);
  const scopes = getScopesFrom('c-scopes');
  const pkce   = $('c-pkce').classList.contains('on');
  const id_token_ttl     = parseInt($('c-id-ttl').value) || 3600;
  const access_token_ttl = parseInt($('c-at-ttl').value) || 3600;
  if (!name)        return toast('Name required', 'err');
  if (!uris.length) return toast('At least one redirect URI required', 'err');
  try {
    const c = await api('/admin/clients', {method:'POST', body:JSON.stringify({
      name, redirect_uris:uris, scopes, pkce, id_token_ttl, access_token_ttl
    })});
    closeModal('modal-add-client');
    $('rc-id').textContent = c.client_id;
    $('rc-secret').textContent = c.client_secret;
    openModal('modal-client-created');
    loadClients();
  } catch (e) { toast(e.message, 'err'); }
}

function openEditClient(idx) {
  const c = _clientsCache[idx];
  _editClientId = c.client_id;
  $('ec-id-display').textContent = c.client_id;
  $('ec-name').value = c.name || '';
  $('ec-uris').value = (c.redirect_uris || []).join('\n');
  $('ec-id-ttl').value = c.id_token_ttl || 3600;
  $('ec-at-ttl').value = c.access_token_ttl || 3600;
  setScopesIn('ec-scopes', c.scopes || ['openid','profile','email']);
  if (c.pkce !== false) $('ec-pkce').classList.add('on');
  else $('ec-pkce').classList.remove('on');
  initScopeTags('ec-scopes');
  openModal('modal-edit-client');
  setTimeout(() => $('ec-name').focus(), 60);
}

async function submitEditClient() {
  const name   = $('ec-name').value.trim();
  const uris   = $('ec-uris').value.split('\n').map(s => s.trim()).filter(Boolean);
  const scopes = getScopesFrom('ec-scopes');
  const pkce   = $('ec-pkce').classList.contains('on');
  const id_token_ttl     = parseInt($('ec-id-ttl').value) || 3600;
  const access_token_ttl = parseInt($('ec-at-ttl').value) || 3600;
  if (!name)        return toast('Name required', 'err');
  if (!uris.length) return toast('At least one redirect URI required', 'err');
  try {
    await api(`/admin/clients/${_editClientId}`, {method:'PATCH', body:JSON.stringify({
      name, redirect_uris:uris, scopes, pkce, id_token_ttl, access_token_ttl
    })});
    closeModal('modal-edit-client');
    toast('Client updated');
    loadClients();
  } catch (e) { toast(e.message, 'err'); }
}

async function doRotateFromEdit() {
  if (!_editClientId) return;
  if (!confirm('Generate new client_secret? Old secret stops working immediately.')) return;
  try {
    const d = await api(`/admin/clients/${_editClientId}/rotate-secret`, {method:'POST'});
    closeModal('modal-edit-client');
    $('rr-id').textContent     = d.client_id;
    $('rr-secret').textContent = d.client_secret;
    openModal('modal-secret-rotated');
    toast('Secret rotated');
  } catch (e) { toast(e.message, 'err'); }
}

async function delClient(id, name) {
  if (!confirm(`Delete client "${name}"?`)) return;
  try {
    await api(`/admin/clients/${id}`, {method:'DELETE'});
    toast(`Client "${name}" deleted`);
    loadClients();
  } catch (e) { toast(e.message, 'err'); }
}

/* -- expose to onclick handlers -- */
window.loadAudit        = loadAudit;
window.auditPrevPage    = auditPrevPage;
window.auditNextPage    = auditNextPage;
window.auditChangeLimit = auditChangeLimit;
window.connectAndSave    = connectAndSave;
window.checkHealth       = checkHealth;
window.checkHealthDebounced = checkHealthDebounced;
window.applyAuditFilter = applyAuditFilter;
window.toggleAuditRow   = toggleAuditRow;
window.togglePkce       = togglePkce;
window.showPage         = showPage;
window.openModal        = openModal;
window.closeModal       = closeModal;
window.copyText         = copyText;
window.toggleTheme      = toggleTheme;
window.openInviteUser   = openInviteUser;
window.submitInviteUser = submitInviteUser;
window.openAddUser      = openAddUser;
window.submitAddUser    = submitAddUser;
window.openEditUser     = openEditUser;
window.submitEditUser   = submitEditUser;
window.addClaimRow      = addClaimRow;
window.requestEnrollment = requestEnrollment;
window.delUser          = delUser;
window.openAddClient    = openAddClient;
window.submitAddClient  = submitAddClient;
window.openEditClient   = openEditClient;
window.submitEditClient = submitEditClient;
window.doRotateFromEdit = doRotateFromEdit;
window.delClient        = delClient;

/* -- boot -- */
/* -- connect & save config -- */
async function connectAndSave() {
  let url = $('api-base').value.trim();
  if (url && !url.startsWith('http')) url = 'https://' + url;
  $('api-base').value = url;
  try {
    const r = await fetch(url + '/health');
    if (!r.ok) throw 0;
    localStorage.setItem('encedo-api-base',   url);
    localStorage.setItem('encedo-api-secret', $('api-secret').value);
    $('status-text').textContent = '✔ saved — reloading…';
    setTimeout(() => location.reload(), 1200);
  } catch {
    $('status-text').textContent = 'unreachable — not saved';
  }
}

/* ==================== INVITES ==================== */

function fmtTtl(seconds) {
  if (seconds < 0) return 'expired';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

async function loadInvites() {
  const b = $('invites-body');
  b.innerHTML = '<div class="loading-row"><span class="spinner"></span></div>';
  try {
    const list = await api('/admin/invites');
    $('invites-sub').textContent = `${list.length} active invite${list.length !== 1 ? 's' : ''}`;
    if (list.length === 0) {
      b.innerHTML = '<div class="empty"><div class="empty-icon">✉</div>No active invites</div>';
      return;
    }
    const cols = 'grid-template-columns:110px 70px 1fr 1.1fr 1.3fr 90px 42px;';
    const typeBadge = t => t === 'client'
      ? '<span style="font-family:var(--mono);font-size:9px;padding:2px 7px;border-radius:5px;background:rgba(110,53,140,.12);color:var(--accent)">client</span>'
      : '<span style="font-family:var(--mono);font-size:9px;padding:2px 7px;border-radius:5px;background:rgba(52,216,154,.1);color:var(--green)">user</span>';
    b.innerHTML = list.map(inv => `
      <div class="table-row" style="${cols}">
        <div class="cell-mono">${esc(inv.token.slice(0, 8))}…</div>
        <div>${typeBadge(inv.type)}</div>
        <div class="cell-muted">${esc(inv.client_name) || '<span style="opacity:.4">—</span>'}</div>
        <div class="cell-muted">${esc(inv.username) || '<span style="opacity:.4">—</span>'}</div>
        <div class="cell-muted">${esc(inv.email) || '<span style="opacity:.4">—</span>'}</div>
        <div class="cell-muted">${fmtTtl(inv.ttl)}</div>
        <div class="cell-actions">
          <button class="btn btn-danger btn-xs" data-inv-type="${inv.type}" data-inv-token="${esc(inv.token)}" onclick="deleteInvite(this)">🗑</button>
        </div>
      </div>`).join('');
  } catch (e) {
    b.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

async function deleteInvite(btn) {
  if (!confirm('Revoke this invite?')) return;
  const type  = btn.dataset.invType;
  const token = btn.dataset.invToken;
  const endpoint = type === 'client'
    ? `/admin/client-invites/${encodeURIComponent(token)}`
    : `/admin/invites/${encodeURIComponent(token)}`;
  try {
    await api(endpoint, { method: 'DELETE' });
    toast('Invite revoked');
    loadInvites();
  } catch (e) {
    toast(e.message, 'err');
  }
}

window.openInviteClient = function() {
  $('invc-note').value = '';
  openModal('modal-invite-client');
};

window.submitInviteClient = async function() {
  try {
    const note = $('invc-note').value.trim();
    const data = await api('/admin/invite-client', {
      method: 'POST',
      body: JSON.stringify({ note }),
    });
    closeModal('modal-invite-client');
    $('invc-result-url').textContent = data.invite_url;
    openModal('modal-invite-client-link');
    loadInvites();
  } catch (e) {
    toast(e.message, 'err');
  }
};

// Restore theme
if (localStorage.getItem('encedo-theme') === 'light')
  document.documentElement.classList.add('light');

// Restore config (must run before checkHealth/loadUsers)
(function(){
  const savedBase   = localStorage.getItem('encedo-api-base');
  const savedSecret = localStorage.getItem('encedo-api-secret');
  if (savedBase)   document.getElementById('api-base').value   = savedBase;
  if (savedSecret) document.getElementById('api-secret').value = savedSecret;
  if (!savedBase) document.getElementById('api-base').value = window.location.origin;
  // Sync theme icon
  const isLight = document.documentElement.classList.contains('light');
  document.getElementById('theme-icon').textContent  = isLight ? '☾' : '☀';
  document.getElementById('theme-label').textContent = isLight ? 'Dark' : 'Light';
})();

checkHealth();
loadUsers();
