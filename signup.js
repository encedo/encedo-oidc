import { HEM, HemError } from '/hem-sdk.js';

const token = location.hash.slice(1).replace(/^token=/, '');

// State shared between steps
let clientName           = '';
let clientRedirectOrigin = null;
let hem                  = null;

function show(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('visible'));
  document.getElementById(id).classList.add('visible');
}

function setStatus(msg) {
  document.getElementById('enroll-status').textContent = msg;
}

// --- Init: validate invite token ---
if (!token) {
  show('s-invalid');
} else {
  try {
    const r = await fetch(`/signup/prefill?token=${encodeURIComponent(token)}`);
    if (!r.ok) { show('s-invalid'); }
    else {
      const d = await r.json();
      clientName = d.client_name || 'this service';
      document.getElementById('rp-client-name').textContent  = clientName;
      document.getElementById('rp-client-name2').textContent = clientName;
      if (d.username) document.getElementById('su-username').value = d.username;
      if (d.name)     document.getElementById('su-name').value     = d.name;
      if (d.email)    document.getElementById('su-email').value    = d.email;
      show('s-form');
      document.getElementById(d.username ? 'su-name' : 'su-username').focus();
    }
  } catch { show('s-invalid'); }
}

// --- Step 1: Next ---
window.doNext = function() {
  const err = document.getElementById('su-err');
  err.textContent = '';
  const username = document.getElementById('su-username').value.trim();
  const email    = document.getElementById('su-email').value.trim();
  if (!username) { err.textContent = 'Username is required'; return; }
  if (!email)    { err.textContent = 'Email is required';    return; }
  show('s-hsm');
  document.getElementById('su-hsm-url').focus();
};

window.doBack = function() { show('s-form'); };

// --- Step 2: Connect & Enroll ---
window.doEnroll = async function() {
  const btn = document.getElementById('su-enroll-btn');
  const err = document.getElementById('hsm-err');
  err.textContent = '';
  btn.disabled = true;

  const hsm_url  = document.getElementById('su-hsm-url').value.trim();
  const password = document.getElementById('su-password').value;
  const username = document.getElementById('su-username').value.trim();
  const name     = document.getElementById('su-name').value.trim();
  const email    = document.getElementById('su-email').value.trim();

  if (!hsm_url) { err.textContent = 'HSM URL is required'; btn.disabled = false; return; }

  show('s-enrolling');
  hem = new HEM(hsm_url);

  async function authorize(scope) {
    return password
      ? hem.authorizePassword(password, scope)
      : hem.authorizeRemote(scope, { pollInterval: 2000, pollTimeout: 60000 });
  }

  try {
    // Step 0: checkin — verify HSM is reachable
    setStatus('Connecting to HSM…');
    await hem.hemCheckin();

    // Step 1: authorize keymgmt:gen — verifies HSM works + passphrase correct
    setStatus('Authorizing key generation…');
    const genToken = await authorize('keymgmt:gen');

    // HSM verified — create account now
    setStatus('Creating account…');
    const regRes  = await fetch('/signup/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token, username, name, email, hsm_url }),
    });
    const regData = await regRes.json();
    if (!regRes.ok) {
      show('s-hsm');
      err.textContent = regData.error_description || regData.error || `Error ${regRes.status}`;
      btn.disabled = false;
      return;
    }

    const { sub, enrollment_token } = regData;
    clientRedirectOrigin = regData.client_redirect_origin;

    // Step 2: create key pair
    setStatus('Creating key pair…');
    const label    = `Encedo OIDC - ${username}`.slice(0, 32);
    const descrB64 = btoa(`ETSOIDC${sub}`);
    const created  = await hem.createKeyPair(genToken, label, 'ED25519', descrB64);
    const kid      = created.kid;
    if (!kid) throw new Error('No kid in createKeyPair response');

    // Step 3: authorize keymgmt:use:<kid>
    setStatus('Authorizing key access…');
    const useToken = await authorize(`keymgmt:use:${kid}`);

    // Step 4: fetch public key
    setStatus('Fetching public key…');
    const keyInfo = await hem.getPubKey(useToken, kid);
    if (!keyInfo.pubkey) throw new Error('No pubkey in getKey response');
    const pubkeyBytes = Uint8Array.from(atob(keyInfo.pubkey), c => c.charCodeAt(0));
    const pubkey      = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    // Step 5: get challenge + sign it
    setStatus('Signing challenge…');
    const chalRes  = await fetch(`/enrollment/validate?token=${encodeURIComponent(enrollment_token)}`);
    const chalData = await chalRes.json();
    if (!chalRes.ok) throw new Error(chalData.error || 'Failed to get challenge');
    const sigBytes  = await hem.exdsaSign(useToken, kid, chalData.challenge);
    const signature = btoa(String.fromCharCode(...sigBytes))
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // Step 6: attestation (non-fatal)
    setStatus('Fetching attestation…');
    let genuine = null, crt = null;
    try {
      const att = await hem.getAttestation(useToken);
      genuine = att.genuine ?? null;
      crt     = att.crt     ?? null;
    } catch (e) { console.warn('[HEM] attestation non-fatal:', e.message); }

    // Step 7: submit enrollment
    setStatus('Saving…');
    const subRes  = await fetch('/enrollment/submit', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token: enrollment_token, hsm_url, kid, pubkey, signature, genuine, crt }),
    });
    const subData = await subRes.json();
    if (!subRes.ok) throw new Error(subData.error || 'Enrollment submission failed');

    // Done!
    document.getElementById('done-username').textContent = username;
    document.getElementById('done-client').textContent   = clientName;
    if (!clientRedirectOrigin) {
      document.getElementById('done-close-btn').style.display = 'none';
    }
    show('s-done');

  } catch (e) {
    console.error('[Signup] failed:', e);
    show('s-hsm');
    err.textContent = e instanceof HemError
      ? `HSM error (${e.code}): ${e.message}`
      : `Error: ${e.message}`;
    btn.disabled = false;
  }
};

window.doClose = function() {
  if (clientRedirectOrigin) window.location.href = clientRedirectOrigin;
};
