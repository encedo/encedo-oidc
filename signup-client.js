const token = location.hash.slice(1).replace(/^token=/, '');

function show(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('visible'));
  document.getElementById(id).classList.add('visible');
}

// --- Init: validate invite token ---
if (!token) {
  show('s-invalid');
} else {
  try {
    const r = await fetch(`/signup-client/prefill?token=${encodeURIComponent(token)}`);
    if (!r.ok) { show('s-invalid'); }
    else {
      show('s-form');
      document.getElementById('sc-name').focus();
    }
  } catch { show('s-invalid'); }
}

// --- Scope / PKCE toggles ---
window.toggleScope = function(el) {
  el.classList.toggle('on');
};

window.togglePkce = function() {
  document.getElementById('pkce-row').classList.toggle('on');
};

// --- Copy helper ---
window.copyVal = function(id) {
  navigator.clipboard.writeText(document.getElementById(id).textContent);
};

// --- Register ---
window.doRegister = async function() {
  const btn = document.getElementById('sc-register-btn');
  const err = document.getElementById('sc-err');
  err.textContent = '';
  btn.disabled = true;

  const name = document.getElementById('sc-name').value.trim();
  const urisRaw = document.getElementById('sc-uris').value;
  const redirect_uris = urisRaw.split('\n').map(s => s.trim()).filter(Boolean);
  const scopes = ['openid',
    ...Array.from(document.querySelectorAll('.scope-tag[data-scope].on'))
      .map(el => el.dataset.scope),
  ];
  const pkce = document.getElementById('pkce-row').classList.contains('on');

  if (!name) { err.textContent = 'Application name is required'; btn.disabled = false; return; }
  if (!redirect_uris.length) { err.textContent = 'At least one redirect URI is required'; btn.disabled = false; return; }

  try {
    const res = await fetch('/signup-client/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token, name, redirect_uris, scopes, pkce }),
    });
    const data = await res.json();
    if (!res.ok) {
      err.textContent = data.error_description || data.error || `Error ${res.status}`;
      btn.disabled = false;
      return;
    }
    document.getElementById('done-client-id').textContent     = data.client_id;
    document.getElementById('done-client-secret').textContent = data.client_secret;
    show('s-done');
  } catch (e) {
    err.textContent = `Error: ${e.message}`;
    btn.disabled = false;
  }
};
