// Browser end-to-end test of single sign-on on the sign-in page, with a fake
// HEM (test/e2e/fake-hem.mjs) standing in for the device and the broker.
// Needs: redis-server, chromium on PATH (or CHROME=/path). Not part of
// `npm test` (CI has no browser):   node test/e2e/sso.mjs
//
// Flow A: full sign-in to client A (password path) with "remember" -> the
//         page caches the HEM token the device issued for 8 h.
// Flow B: sign-in to client B is the accounts screen + one click; the
//         id_token carries amr [hwk, sso] and auth_time of flow A.
// Flow C: RP-initiated logout on the OP clears the session in the browser.
// Fallback: a token the device no longer accepts drops the session and turns
//         into a fresh, interactive sign-in.
import assert from 'node:assert/strict';
import { spawn, execSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import crypto from 'node:crypto';
import { startFakeHem } from './fake-hem.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const REDIS_PORT = 6398, APP_PORT = 3398, CDP_PORT = 9223;
const BASE   = `http://localhost:${APP_PORT}`;
const SECRET = 'e2e-secret';
const H = { Authorization: `Bearer ${SECRET}`, 'Content-Type': 'application/json' };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const jpost = (p, b, h = H) => fetch(BASE + p, { method: 'POST', headers: h, body: JSON.stringify(b) }).then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));
const jwtPayload = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());
const portOpen = (port) => new Promise(res => { const s = net.connect(port, '127.0.0.1'); s.on('connect', () => { s.destroy(); res(true); }); s.on('error', () => res(false)); });
async function waitPort(port, tries = 100) {
  for (let i = 0; i < tries; i++) {
    if (await portOpen(port)) return;
    await sleep(100);
  }
  throw new Error(`port ${port} never came up`);
}
// The browser is closed through CDP, not with a signal: a snap-packaged
// chromium is a launcher whose real chrome our process may not be allowed to
// kill (AppArmor), and a survivor keeps its profile -- and the cached session.
async function closeBrowser() {
  try {
    const v = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`)).json();
    const ws = new WebSocket(v.webSocketDebuggerUrl);
    await new Promise(r => ws.onopen = r);
    ws.send(JSON.stringify({ id: 1, method: 'Browser.close' }));
    await sleep(500); ws.close();
  } catch { /* already gone */ }
}

// ---- infrastructure ------------------------------------------------------------
const procs = [];
const dir = mkdtempSync(join(tmpdir(), 'oidc-e2e-'));
procs.push(spawn('redis-server', ['--port', String(REDIS_PORT), '--dir', dir, '--save', '', '--appendonly', 'no'], { stdio: 'ignore' }));
await waitPort(REDIS_PORT);

// software Ed25519 key that the fake device "holds" and the OP will enroll
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pubRaw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
const pubHex = pubRaw.toString('hex');
const kid    = crypto.createHash('sha1').update(pubRaw).digest('hex').slice(0, 32);

const hem = await startFakeHem({ keys: [] });   // descr filled in once the user's sub is known
procs.push({ kill: () => hem.close() });

procs.push(spawn('node', ['src/app.js'], { cwd: ROOT, stdio: 'ignore', env: { ...process.env,
  REDIS_URL: `redis://127.0.0.1:${REDIS_PORT}`, PORT: String(APP_PORT), ISSUER: BASE, ADMIN_SECRET: SECRET,
  ADMIN_ALLOWED_IPS: '127.0.0.1,::1', CSP_CONNECT_EXTRA: hem.deviceUrl, SSO_SUGGEST_SECONDS: '28800' } }));
await waitPort(APP_PORT);

const chrome = process.env.CHROME || 'chromium';
if (await portOpen(CDP_PORT)) throw new Error(`port ${CDP_PORT} is already in use -- a chromium from an earlier run? (its profile would carry a stale session)`);
const profile = mkdtempSync(join(tmpdir(), 'oidc-e2e-chrome-'));
procs.push(spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' }));
await waitPort(CDP_PORT);

// ---- minimal CDP driver --------------------------------------------------------
async function openPage() {
  const t = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/new?about:blank`, { method: 'PUT' })).json();
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise(r => ws.onopen = r);
  let id = 0; const pend = new Map(); const errors = [];
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
    if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text);
    // network-level failures (an expected 401 from the device, a 404 favicon) are not page errors; CSP violations and exceptions are
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error' && !/^Failed to load resource/.test(m.params.entry.text)) errors.push(m.params.entry.text);
  };
  const send = (method, params = {}) => new Promise(r => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  await send('Runtime.enable'); await send('Log.enable'); await send('Page.enable');
  const evalJs = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error('page: ' + (r.result.exceptionDetails.exception?.description ?? r.result.exceptionDetails.text));
    return r.result?.result?.value;
  };
  const goto = async (url) => { await send('Page.navigate', { url }); await sleep(800); };
  const until = async (expr, what, ms = 15000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) { let v; try { v = await evalJs(expr); } catch { v = undefined; } if (v) return v; await sleep(200); }
    throw new Error(`timeout waiting for ${what}: last screen=${await evalJs("document.querySelector('.screen.visible')?.id").catch(() => '?')} errors=${JSON.stringify(errors)}`);
  };
  const click = (sel) => evalJs(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error('no ' + ${JSON.stringify(sel)}); e.click(); return true; })()`);
  const type  = (sel, v) => evalJs(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  const screen = () => evalJs("document.querySelector('.screen.visible')?.id");
  return { evalJs, goto, until, click, type, screen, errors, close: () => ws.close() };
}

// ---- OP setup ------------------------------------------------------------------
let failed = false;
try {
  const mkClient = (name) => jpost('/admin/clients', { name, redirect_uris: [hem.rpCallback], post_logout_redirect_uris: [hem.rpBye], scopes: ['openid', 'email'], pkce: false }).then(r => r.body);
  const A = await mkClient('App A'), B = await mkClient('App B');
  const user = (await jpost('/admin/users', { username: 'krutecki', name: 'Krzysztof', email: 'k@e2e.test', hsm_url: hem.deviceUrl, clients: [A.client_id, B.client_id] })).body;
  const enrollToken = user.enrollment_url.split('#token=')[1];
  const chal = (await jpost('/enrollment/validate', { token: enrollToken })).body.challenge;
  const enr = await jpost('/enrollment/submit', { token: enrollToken, hsm_url: hem.deviceUrl, kid, pubkey: pubHex, key_type: 'Ed25519', signature: crypto.sign(null, Buffer.from(chal), privateKey).toString('base64url') });
  assert.equal(enr.status, 200, 'enrollment');
  hem.state.keys.push({ kid, label: 'Encedo OIDC - krutecki', descr: 'ETSOIDC' + user.sub, privateKey });

  const authz = (client, extra = {}) => `${BASE}/authorize?` + new URLSearchParams({ client_id: client.client_id, redirect_uri: hem.rpCallback, response_type: 'code', scope: 'openid email', state: 'st-' + client.name.slice(-1), nonce: 'n1', hem_broker: hem.brokerUrl, ...extra });
  const exchange = (client, code) => jpost('/token', { grant_type: 'authorization_code', code, redirect_uri: hem.rpCallback, client_id: client.client_id, client_secret: client.client_secret });
  const page = await openPage();

  // ---- Flow A: full sign-in to A, remember ----------------------------------
  console.log('A: full sign-in (password path), remember in this browser');
  await page.goto(authz(A));
  assert.equal(await page.screen(), 's-login');
  await page.type('#hsm-url-input', hem.deviceUrl);
  await page.click('[data-action=do-login]');
  await page.until("document.querySelector('.screen.visible')?.id === 's-token-confirm'", 'confirm screen');
  assert.equal(await page.evalJs("document.getElementById('tc-remember').checked"), true);
  assert.equal(await page.evalJs("document.getElementById('tc-remember-hours').textContent"), '8');
  assert.equal(await page.evalJs("document.getElementById('tc-remember-row').style.display"), '');
  await page.click('[data-action=do-approve-sign]');
  await page.until("document.querySelector('.screen.visible')?.id === 's-pin'", 'passphrase screen (no mobile app on this device)');
  await page.type('#pin-input', 'correct horse');
  await page.click('[data-action=do-submit-pin]');
  const entryKey = await page.until("Object.keys(localStorage).find(k => k.startsWith('encedo_sso:'))", 'SSO entry saved (during the countdown)');
  const entry = JSON.parse(await page.evalJs(`localStorage.getItem(${JSON.stringify(entryKey)})`));
  assert.equal(entry.kid, kid); assert.equal(entry.username, 'krutecki'); assert.equal(entry.sub, user.sub);
  const authA = hem.state.issued.at(-1);
  assert.equal(authA.exp - authA.iat, 28800, 'page asked the device for the suggested 8 h');
  assert.equal(entry.exp, authA.exp, 'entry exp comes from the token the device issued');
  assert.equal(entry.iat, authA.iat);
  await page.until("location.href.includes('/cb?')", 'redirect to RP A');
  const codeA = hem.state.callbacks.at(-1).code; assert.ok(codeA); assert.equal(hem.state.callbacks.at(-1).state, 'st-A');
  const tokA = await exchange(A, codeA); assert.equal(tokA.status, 200);
  const pA = jwtPayload(tokA.body.id_token);
  assert.deepEqual(pA.amr, ['hwk']); assert.equal(pA.email, 'k@e2e.test');
  console.log('   ok: amr', pA.amr, 'auth_time', pA.auth_time, 'entry until', new Date(entry.exp * 1000).toISOString());

  // ---- Flow B: one click into B --------------------------------------------
  console.log('B: sign-in to App B from the accounts screen');
  const signsBefore = hem.state.log.filter(l => l.path === '/api/crypto/exdsa/sign').length;
  const authsBefore = hem.state.log.filter(l => l.path === '/api/auth/token' && l.method === 'POST').length;
  await page.goto(authz(B));
  assert.equal(await page.screen(), 's-accounts');
  assert.equal(await page.evalJs("document.querySelectorAll('#acct-list .acct').length"), 1);
  assert.match(await page.evalJs("document.querySelector('.acct-name').textContent"), /krutecki/);
  await page.click('#acct-list .acct');
  await page.until("location.href.includes('/cb?')", 'redirect to RP B');
  assert.equal(hem.state.log.filter(l => l.path === '/api/auth/token' && l.method === 'POST').length, authsBefore, 'no new authorization on the device');
  assert.equal(hem.state.log.filter(l => l.path === '/api/crypto/exdsa/sign').length, signsBefore + 1, 'exactly one signature');
  const codeB = hem.state.callbacks.at(-1).code; assert.equal(hem.state.callbacks.at(-1).state, 'st-B');
  const tokB = await exchange(B, codeB); assert.equal(tokB.status, 200);
  const pB = jwtPayload(tokB.body.id_token);
  assert.deepEqual(pB.amr, ['hwk', 'sso']);
  assert.equal(pB.auth_time, authA.iat, 'auth_time is the original HEM authorization');
  console.log('   ok: amr', pB.amr, 'auth_time', pB.auth_time);

  // ---- prompt=login / max_age refuse the session --------------------------
  console.log('B: prompt=login skips the accounts screen; max_age=1 turns the click into a fresh sign-in');
  await page.goto(authz(B, { prompt: 'login' }));
  assert.equal(await page.screen(), 's-login');
  await page.goto(authz(B, { max_age: '1' }));
  assert.equal(await page.screen(), 's-accounts');
  await page.click('#acct-list .acct');
  await page.until("document.querySelector('.screen.visible')?.id === 's-token-confirm'", 'confirm screen after refusal');
  assert.match(await page.evalJs("document.getElementById('tc-note').textContent"), /more recent sign-in/);
  assert.ok(await page.evalJs("Object.keys(localStorage).some(k => k.startsWith('encedo_sso:'))"), 'a policy refusal keeps the session');

  // ---- Flow C: logout asks; "No" keeps the session, "Yes" clears it ---------
  console.log('C: RP-initiated logout asks whether to end the Encedo session too');
  const logoutUrl = `${BASE}/logout?` + new URLSearchParams({ id_token_hint: tokB.body.id_token, post_logout_redirect_uri: hem.rpBye, client_id: B.client_id, state: 'z' });
  await page.goto(logoutUrl);
  await page.until("!document.getElementById('lo-ask')?.hidden", 'the question');
  assert.equal(await page.evalJs("document.getElementById('lo-ask-title').textContent"), 'You have been signed out of App B.');
  assert.equal(await page.evalJs("document.getElementById('lo-yes').textContent"), 'Yes, sign out \u201Ckrutecki\u201D too');
  assert.equal(await page.evalJs("document.getElementById('lo-no').textContent"), 'No, keep \u201Ckrutecki\u201D signed in');
  assert.match(await page.evalJs("document.getElementById('lo-ask-text').textContent"), /^\u201Ckrutecki\u201D is still signed in on this browser\./);
  assert.equal(await page.evalJs("document.getElementById('lo-done').hidden"), true);
  await page.click('#lo-no');
  await page.until("location.href.includes('/bye')", 'post-logout redirect after "No"');
  assert.match(await page.evalJs('location.href'), /\/bye\?state=z$/);
  await page.goto(authz(A));   // back on the OP origin, where the session lives
  assert.equal(await page.evalJs("Object.keys(localStorage).filter(k => k.startsWith('encedo_sso:')).length"), 1, '"No" keeps the session');
  assert.equal(await page.screen(), 's-accounts', 'session still usable after "No"');
  console.log('   ok: "No" kept the session');
  await page.goto(logoutUrl);
  await page.until("!document.getElementById('lo-ask')?.hidden", 'the question again');
  await page.click('#lo-yes');
  await page.until("location.href.includes('/bye')", 'post-logout redirect after "Yes"');
  assert.match(await page.evalJs('location.href'), /\/bye\?state=z$/);
  await page.goto(authz(A));
  assert.equal(await page.screen(), 's-login', 'no session after "Yes"');
  assert.equal(await page.evalJs("Object.keys(localStorage).filter(k => k.startsWith('encedo_sso:')).length"), 0);
  console.log('   ok: "Yes" cleared it');
  // nothing kept in this browser: no question, straight to the RP
  await page.goto(logoutUrl);
  await page.until("location.href.includes('/bye')", 'immediate redirect with nothing to ask about');
  await page.goto(authz(A));   // back on the OP origin for the steps below
  assert.equal(await page.screen(), 's-login');

  // ---- Fallback: device refuses the cached token ---------------------------
  console.log('Fallback: device no longer accepts the token -> fresh sign-in, session dropped');
  await page.evalJs(`localStorage.setItem(${JSON.stringify(entryKey)}, ${JSON.stringify(JSON.stringify(entry))})`);
  hem.state.revoked = true;
  await page.goto(authz(B));
  assert.equal(await page.screen(), 's-accounts');
  await page.click('#acct-list .acct');
  await page.until("document.querySelector('.screen.visible')?.id === 's-token-confirm'", 'confirm screen after device 401');
  assert.match(await page.evalJs("document.getElementById('tc-note').textContent"), /session has ended/);
  assert.equal(await page.evalJs("Object.keys(localStorage).filter(k => k.startsWith('encedo_sso:')).length"), 0, 'refused token is forgotten');
  hem.state.revoked = false;

  // ---- user.sso=false: nothing is cached -----------------------------------
  console.log('Policy: user.sso=false hides "remember" and nothing is cached');
  await fetch(`${BASE}/admin/users/${user.sub}`, { method: 'PATCH', headers: H, body: JSON.stringify({ sso: false }) });
  await page.goto(authz(A));
  await page.type('#hsm-url-input', hem.deviceUrl);
  await page.click('[data-action=do-login]');
  await page.until("document.querySelector('.screen.visible')?.id === 's-token-confirm'", 'confirm screen');
  assert.equal(await page.evalJs("document.getElementById('tc-remember-row').style.display"), 'none');
  await page.click('[data-action=do-approve-sign]');
  await page.until("document.querySelector('.screen.visible')?.id === 's-pin'", 'passphrase screen');
  await page.type('#pin-input', 'correct horse');
  await page.click('[data-action=do-submit-pin]');
  await page.until("location.href.includes('/cb?')", 'redirect to RP A');
  await page.goto(authz(B));
  assert.equal(await page.screen(), 's-login', 'no accounts screen for a user without SSO');
  assert.equal(hem.state.issued.at(-1).exp - hem.state.issued.at(-1).iat, 300, 'device asked for the short default lifetime');

  assert.deepEqual(page.errors, [], 'no page errors (exceptions, CSP)');
  console.log('\nPASS: SSO flows A, B, C, fallback, policy');
  page.close();
} catch (e) {
  failed = true;
  console.error('\nFAIL:', e.message);
} finally {
  await closeBrowser();
  for (const p of procs) { try { p.kill(); } catch { /* gone */ } }
  try { execSync(`rm -rf ${profile} ${dir}`); } catch { /* best effort */ }
}
process.exit(failed ? 1 : 0);
