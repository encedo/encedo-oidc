/**
 * local-network.js -- Chromium's Local Network Access, before the first HEM request.
 *
 * A page on a public site (oidc.encedo.com) that fetches a device on the
 * user's own network (my.ence.do -> 192.168.7.1) makes Chromium ask the user
 * "allow access to devices on your local network?". Measured in Chromium 156
 * (2026-11-07): the request that triggered the question WAITS while it is
 * open and then FAILS whatever the answer; only the next request goes through.
 * Headers on the device do not change that -- the user decides.
 *
 * ensureLocalNetwork(hsmUrl) therefore, before the page's real HEM calls:
 *   - does nothing where there is nothing to ask: a browser without the
 *     permission (Firefox, Safari), permission already granted, a page that is
 *     itself on a local address, a HEM on a public address (EPA cloud domain);
 *   - 'prompt': tells the user what to choose, sends a throwaway request that
 *     raises the question, and on 'granted' sends one more to be sure;
 *   - 'denied' (now or after the answer): explains how to allow it, per
 *     browser, with Try again / Cancel;
 *   - question closed without an answer: says so, Try again / Cancel.
 * Throws an Error with code 'lna_denied' (Cancel on the blocked notice) or
 * 'lna_cancelled' (Cancel after an unanswered question); hemErrMsg() has the messages.
 *
 * A UI file: route in src/app.js, COPY in the Dockerfile, release.yml list.
 * Styles are inline (style-src-attr allows them), so no CSP hash changes.
 */

const PERMISSION = 'local-network-access';

function lnaError(code, message) {
  return Object.assign(new Error(message), { code });
}

/** The page itself on loopback / a private address: no "more private" target exists. */
function pageIsLocal() {
  const h = location.hostname.replace(/^\[(.*)\]$/, '$1');
  return h === 'localhost' || h.endsWith('.localhost') || /^127\./.test(h) || h === '::1'
    || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
}

async function permissionStatus() {
  try { return await navigator.permissions.query({ name: PERMISSION }); }
  catch { return null; }   // this browser has no such permission: nothing will be asked
}

async function hemSpace(host) {
  try {
    const r = await fetch('/hem/address-space', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host }) });
    if (!r.ok) return 'unresolved';
    return (await r.json()).space ?? 'unresolved';
  } catch { return 'unresolved'; }
}

/** One cheap request to the HEM; true when it answered. */
async function probe(hsmUrl) {
  try {
    const r = await fetch(new URL('/api/system/version', hsmUrl), { cache: 'no-store' });
    return r.ok;
  } catch { return false; }
}

// --- browser-specific instructions for a blocked permission -------------------------

function browserName() {
  const brands = (navigator.userAgentData?.brands ?? []).map(b => b.brand);
  for (const b of ['Microsoft Edge', 'Brave', 'Opera', 'Google Chrome']) if (brands.includes(b)) return b;
  if (brands.includes('Chromium')) return 'Chromium';
  return 'your browser';
}

function unblockSteps() {
  const name = browserName();
  const steps = [
    'Click the icon at the left end of the address bar (site information).',
    'Set <b>Local network</b> to <b>Allow</b>. If it is not listed there, open <b>Site settings</b> and change it there.',
    'Come back here and press <b>Try again</b>.',
  ];
  // Verified in Chromium 156: the setting is "Local network", page chrome://settings/content/localNetwork.
  // Other Chromium browsers may word it differently -- no page address is given for them.
  const page = (name === 'Google Chrome' || name === 'Chromium')
    ? '<p style="margin:10px 0 0;font-size:12.5px;color:var(--muted,#666)">All sites: <code>chrome://settings/content/localNetwork</code> (copy into the address bar).</p>'
    : '';
  return `<ol style="margin:10px 0 0;padding-left:20px;line-height:1.55">${steps.map(s => `<li>${s}</li>`).join('')}</ol>${page}`;
}

// --- modal ------------------------------------------------------------------------------

let current = null;

function closeModal() { current?.remove(); current = null; }

/**
 * Show the modal; resolves with the pressed button's value ('retry' / 'cancel'),
 * or never for a modal without buttons (closed by the caller).
 */
function showModal({ title, html, buttons = [] }) {
  closeModal();
  const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const overlay = document.createElement('div');
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-labelledby', 'lna-title');
  overlay.style.cssText = 'position:fixed;inset:0;z-index:10000;background:rgba(20,16,58,.45);display:flex;align-items:center;justify-content:center;padding:16px;';
  const box = document.createElement('div');
  box.style.cssText = 'background:var(--white,#fff);color:var(--text,#222);border-radius:14px;max-width:440px;width:100%;padding:22px 22px 18px;box-shadow:0 12px 40px rgba(0,0,0,.25);font-size:14px;line-height:1.5;text-align:left;';
  box.innerHTML = `<div id="lna-title" style="font-weight:700;font-size:16px;color:var(--navy,#2A225E);margin-bottom:8px">${esc(title)}</div><div>${html}</div>`;
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;margin-top:18px;';
  const done = new Promise((resolve) => {
    for (const b of buttons) {
      const el = document.createElement('button');
      el.type = 'button';
      el.textContent = b.label;
      if (b.primary) {
        el.className = 'btn btn-primary';             // the page's own button style
        el.style.cssText = 'width:auto;margin:0;';
      } else {
        el.style.cssText = 'background:transparent;border:1px solid var(--border,#ccc);color:var(--text,#222);border-radius:10px;padding:10px 16px;font:inherit;cursor:pointer;';
      }
      el.addEventListener('click', () => resolve(b.value));
      row.appendChild(el);
    }
  });
  if (buttons.length) box.appendChild(row);
  overlay.appendChild(box);
  document.body.appendChild(overlay);
  current = overlay;
  overlay.querySelector('button.btn-primary')?.focus();
  return done;
}

// --- the step every page runs before talking to the HEM -------------------------------

export async function ensureLocalNetwork(hsmUrl) {
  let host;
  try { host = new URL(hsmUrl).hostname.replace(/^\[(.*)\]$/, '$1'); } catch { return; }   // the real call reports a bad URL
  if (pageIsLocal()) return;
  const status = await permissionStatus();
  if (!status || status.state === 'granted') return;
  const space = await hemSpace(host);
  if (space === 'public') return;

  const hostHtml = `<code>${host.replace(/[&<>"']/g, '')}</code>`;
  let state = status.state;
  try {
    for (;;) {
      if (state === 'granted') { await probe(hsmUrl); return; }   // the page's own call reports any other failure

      if (state === 'denied') {
        const choice = await showModal({
          title: 'Local network access is blocked',
          html: `<p style="margin:0">Your HEM (${hostHtml}) is a device on your own network, and ${browserName()} does not let this site reach devices on your local network, so this page cannot talk to it.</p>${unblockSteps()}`,
          buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Try again', value: 'retry', primary: true }],
        });
        if (choice === 'cancel') throw lnaError('lna_denied', 'Local network access is blocked in the browser.');
        closeModal();
        state = (await permissionStatus())?.state ?? 'granted';   // the setting may have been changed in another tab
        continue;
      }

      // 'prompt': say what is coming, then raise the browser's question with a throwaway request.
      showModal({
        title: 'Allow access to your HEM',
        html: `<p style="margin:0">Your HEM (${hostHtml}) is a device on your own network. Your browser is about to ask whether this site may access devices on your local network.</p><p style="margin:10px 0 0"><b>Choose “Allow”.</b> Waiting for your answer…</p>`,
      });
      if (await probe(hsmUrl)) return;   // no question after all
      state = (await permissionStatus())?.state ?? 'granted';
      if (state !== 'prompt') continue;  // answered: granted -> one more request, denied -> instructions

      const choice = await showModal({
        title: 'No answer given',
        html: '<p style="margin:0">The browser’s question was closed without an answer, so this page still cannot reach your HEM. Press <b>Try again</b> and choose <b>Allow</b>.</p>',
        buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Try again', value: 'retry', primary: true }],
      });
      if (choice === 'cancel') throw lnaError('lna_cancelled', 'Cancelled.');
    }
  } finally {
    closeModal();
  }
}
