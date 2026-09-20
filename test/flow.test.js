// Integration tests: the real OIDC flows against a live app + Redis, driven by
// a SOFTWARE Ed25519 key (no HSM). Self-contained -- spawns its own redis-server
// and app process on fixed test ports, and SKIPS cleanly if redis-server is not
// installed (so `npm test` never breaks without it; CI installs it).
//
//   npm test   (or: node --test test/flow.test.js)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';

const REDIS_PORT = 6399;
const APP_PORT   = 3399;
const BASE       = `http://127.0.0.1:${APP_PORT}`;
const SECRET     = 'test-secret';

let hasRedis = true;
try { execSync('command -v redis-server', { stdio: 'ignore' }); } catch { hasRedis = false; }
const opt = hasRedis ? {} : { skip: 'redis-server not installed' };

let redisProc, appProc, redisDir;
const REDIS_ARGS = () => ['--port', String(REDIS_PORT), '--dir', redisDir, '--save', '', '--appendonly', 'no'];

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const b64url = (b) => Buffer.from(b).toString('base64url');

async function waitPort(port, tries = 50) {
  for (let i = 0; i < tries; i++) {
    const up = await new Promise(res => {
      const s = net.connect(port, '127.0.0.1');
      s.on('connect', () => { s.destroy(); res(true); });
      s.on('error', () => res(false));
    });
    if (up) return;
    await sleep(100);
  }
  throw new Error(`port ${port} never came up`);
}
async function waitHealth(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try { if ((await fetch(BASE + '/health')).ok) return; } catch { /* not yet */ }
    await sleep(100);
  }
  throw new Error('app /health never came up');
}

const H = { Authorization: `Bearer ${SECRET}`, 'Content-Type': 'application/json' };
const jpost = (p, b, h = H) => fetch(BASE + p, { method: 'POST', headers: h, body: JSON.stringify(b) })
  .then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));
const jget  = (p, h = H) => fetch(BASE + p, { headers: h })
  .then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));
// Same as jpost/jget but keeps the response headers (Cache-Control, WWW-Authenticate).
const rpost = (p, b, h = H) => fetch(BASE + p, { method: 'POST', headers: h, body: JSON.stringify(b) })
  .then(async r => ({ status: r.status, headers: r.headers, body: await r.json().catch(() => null) }));
const rget  = (p, h = {}) => fetch(BASE + p, { headers: h, redirect: 'manual' })
  .then(async r => ({ status: r.status, headers: r.headers, body: await r.json().catch(() => null) }));

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'); // 32 bytes
  return {
    pubHex: raw.toString('hex'),
    kid:    crypto.createHash('sha1').update(raw).digest('hex').slice(0, 32),
    sign:   (m) => crypto.sign(null, Buffer.from(m), privateKey).toString('base64url'),
  };
}

// Create a user (Add), return { sub, enrollToken }.
async function addUser(username, clients = []) {
  const r = await jpost('/admin/users', { username, name: 'T U', email: `${username}@f.com`, hsm_url: 'https://sw.ence.do', clients });
  return { sub: r.body.sub, enrollToken: r.body.enrollment_url.split('#token=')[1].split('&')[0] };
}

before(async () => {
  if (!hasRedis) return;
  redisDir  = mkdtempSync(join(tmpdir(), 'oidc-test-'));
  redisProc = spawn('redis-server', REDIS_ARGS(), { stdio: 'ignore' });
  await waitPort(REDIS_PORT);
  appProc = spawn('node', ['src/app.js'], {
    stdio: 'ignore',
    env: { ...process.env, REDIS_URL: `redis://127.0.0.1:${REDIS_PORT}`, PORT: String(APP_PORT),
           ISSUER: BASE, ADMIN_SECRET: SECRET, ADMIN_ALLOWED_IPS: '127.0.0.1,::1' },
  });
  await waitHealth();
});

after(() => { try { appProc?.kill(); } catch {} try { redisProc?.kill(); } catch {} });

// A failed /enrollment/submit no longer consumes the token (it is
// compare-and-deleted only once every check passed); the first test below
// still uses fresh tokens per case and the "retry" test relies on the new rule.
async function submitEnroll(enrollToken, key, { kid, signMessage } = {}) {
  // Always call validate: it activates the session and generates the challenge.
  const challenge = (await jpost('/enrollment/validate', { token: enrollToken })).body.challenge;
  return jpost('/enrollment/submit', { token: enrollToken, hsm_url: 'https://sw.ence.do',
    kid: kid ?? key.kid, pubkey: key.pubHex, key_type: 'Ed25519', signature: key.sign(signMessage ?? challenge) });
}

test('enrollment: valid signature enrolls; wrong kid and bad signature are rejected', opt, async () => {
  // wrong kid
  let a = await addUser('enr1'); let k = genKey();
  let r = await submitEnroll(a.enrollToken, k, { kid: 'deadbeefdeadbeefdeadbeefdeadbeef' });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_kid');

  // bad signature (validate runs, but the key signs the wrong message)
  a = await addUser('enr2'); k = genKey();
  r = await submitEnroll(a.enrollToken, k, { signMessage: 'not-the-challenge' });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_enrollment_signature');

  // valid
  a = await addUser('enr3'); k = genKey();
  r = await submitEnroll(a.enrollToken, k);
  assert.equal(r.status, 200, 'valid enrollment must succeed');
  assert.equal(r.body.kid, k.kid);
});

test('login: PKCE S256 + one-time authorization code', opt, async () => {
  // enrolled user, granted the client at creation
  const client = (await jpost('/admin/clients', { name: 'RP', redirect_uris: ['https://rp/cb'], scopes: ['openid', 'email'] })).body;
  const { sub, enrollToken } = await addUser('log1', [client.client_id]);
  const key = genKey();
  assert.equal((await submitEnroll(enrollToken, key)).status, 200);

  // Sign in and get a fresh authorization code. A failed /token consumes the
  // code (getDel before PKCE check), so each case below uses its own code.
  async function getCode() {
    const verifier = b64url(crypto.randomBytes(32));
    const chal     = crypto.createHash('sha256').update(verifier).digest('base64url');
    const login = await jpost('/authorize/login', { sub, client_id: client.client_id, redirect_uri: 'https://rp/cb',
      response_type: 'code', scope: 'openid email', code_challenge: chal, code_challenge_method: 'S256', state: 's', nonce: 'n' });
    assert.equal(login.status, 200, 'login must return signing_input');
    const confirm = await jpost('/authorize/confirm', { session_id: login.body.session_id, signature: key.sign(login.body.signing_input) });
    assert.equal(confirm.status, 200, 'a valid signature must confirm');
    return { code: new URL(confirm.body.redirect_url).searchParams.get('code'), verifier };
  }

  const exchange = (code, verifier) => jpost('/token', { grant_type: 'authorization_code', code,
    redirect_uri: 'https://rp/cb', client_id: client.client_id, client_secret: client.client_secret, code_verifier: verifier });

  // correct PKCE -> tokens; the same code cannot be reused (one-time)
  const c1 = await getCode();
  let tok = await exchange(c1.code, c1.verifier);
  assert.equal(tok.status, 200, 'correct PKCE must return tokens');
  assert.ok(tok.body.id_token && tok.body.access_token);
  assert.notEqual((await exchange(c1.code, c1.verifier)).status, 200, 'an authorization code must not be reusable');

  // wrong PKCE verifier on a fresh code -> rejected
  const c2 = await getCode();
  assert.equal((await exchange(c2.code, b64url(crypto.randomBytes(32)))).status, 400, 'PKCE mismatch must be rejected');
});

test('email_verified: set true only when signup carries the invite nonce', opt, async () => {
  const client = (await jpost('/admin/clients', { name: 'RP2', redirect_uris: ['https://rp2/cb'], scopes: ['openid'] })).body;

  async function signupEnroll(username, sendNonce) {
    const inv = (await jpost('/admin/invite', { clients: [client.client_id], username, email: `${username}@f.com` })).body;
    const token = inv.invite_url.split('#token=')[1];     // admin link has no nonce
    // the emailed link's nonce lives on the record; read it only for the "verified" case
    const nonce = sendNonce ? JSON.parse(execSync(`redis-cli -p ${REDIS_PORT} get invite:${token}`).toString()).email_nonce : '';
    const reg = await jpost('/signup/register', { token, hsm_url: 'https://sw.ence.do', n: nonce });
    const val = await jpost('/enrollment/validate', { token: reg.body.enrollment_token });
    const key = genKey();
    await jpost('/enrollment/submit', { token: reg.body.enrollment_token, hsm_url: 'https://sw.ence.do',
      kid: key.kid, pubkey: key.pubHex, key_type: 'Ed25519', signature: key.sign(val.body.challenge), n: nonce });
    return (await jget('/admin/users')).body.find(u => u.username === username).email_verified;
  }

  assert.equal(await signupEnroll('noemail', false), 'false', 'no nonce -> not verified');
  assert.equal(await signupEnroll('yesemail', true),  'true',  'invite nonce -> verified');
});

// Shared sign-in helper for the token-endpoint tests: enrolls a software key
// for `username`, grants it `client`, and returns a function that mints a
// fresh authorization code (optionally with PKCE).
async function signerFor(username, client) {
  const { sub, enrollToken } = await addUser(username, [client.client_id]);
  const key = genKey();
  assert.equal((await submitEnroll(enrollToken, key)).status, 200);
  return async function getCode({ pkce = true } = {}) {
    const verifier = b64url(crypto.randomBytes(32));
    const chal     = crypto.createHash('sha256').update(verifier).digest('base64url');
    const body = { sub, client_id: client.client_id, redirect_uri: client.redirect_uris[0], response_type: 'code', scope: 'openid', nonce: 'n' };
    if (pkce) Object.assign(body, { code_challenge: chal, code_challenge_method: 'S256' });
    const login = await jpost('/authorize/login', body);
    if (login.status !== 200) return { login };
    const confirm = await jpost('/authorize/confirm', { session_id: login.body.session_id, signature: key.sign(login.body.signing_input) });
    assert.equal(confirm.status, 200);
    return { login, code: new URL(confirm.body.redirect_url).searchParams.get('code'), verifier };
  };
}

test('token: a confidential client must present its secret even when the code carries PKCE', opt, async () => {
  // pkce:false = the client does not REQUIRE PKCE; it is still confidential (public defaults to false)
  const client = (await jpost('/admin/clients', { name: 'Conf', redirect_uris: ['https://conf/cb'], scopes: ['openid'], pkce: false })).body;
  assert.equal(client.public, false, 'clients are confidential by default');
  const getCode = await signerFor('conf1', client);
  const tokenReq = (extra, h = H) => rpost('/token', { grant_type: 'authorization_code', redirect_uri: 'https://conf/cb', client_id: client.client_id, ...extra }, h);

  // PKCE alone (the old bypass) -> invalid_client
  let c = await getCode();
  let r = await tokenReq({ code: c.code, code_verifier: c.verifier });
  assert.equal(r.status, 401); assert.equal(r.body.error, 'invalid_client');
  assert.equal(r.headers.get('cache-control'), 'no-store'); assert.equal(r.headers.get('pragma'), 'no-cache');

  // secret in the body (client_secret_post) + PKCE -> tokens
  c = await getCode();
  r = await tokenReq({ code: c.code, code_verifier: c.verifier, client_secret: client.client_secret });
  assert.equal(r.status, 200, 'secret + PKCE must succeed'); assert.ok(r.body.id_token);
  assert.equal(r.headers.get('cache-control'), 'no-store'); assert.equal(r.headers.get('pragma'), 'no-cache');

  // secret via HTTP Basic (client_secret_basic)
  c = await getCode();
  const basic = 'Basic ' + Buffer.from(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`).toString('base64');
  r = await tokenReq({ code: c.code, code_verifier: c.verifier }, { 'Content-Type': 'application/json', Authorization: basic });
  assert.equal(r.status, 200, 'Basic auth must succeed');

  // wrong secret via Basic -> 401 + WWW-Authenticate matching the scheme
  c = await getCode();
  const bad = 'Basic ' + Buffer.from(`${client.client_id}:nope`).toString('base64');
  r = await tokenReq({ code: c.code, code_verifier: c.verifier }, { 'Content-Type': 'application/json', Authorization: bad });
  assert.equal(r.status, 401); assert.equal(r.body.error, 'invalid_client');
  assert.match(r.headers.get('www-authenticate') ?? '', /^Basic/);

  // no PKCE at all, secret only -> tokens (PKCE is not required for this client)
  c = await getCode({ pkce: false });
  r = await tokenReq({ code: c.code, client_secret: client.client_secret });
  assert.equal(r.status, 200, 'secret without PKCE must succeed for a client that does not require PKCE');
});

test('token: a public client is PKCE-only, and PKCE is mandatory for it', opt, async () => {
  let r = await jpost('/admin/clients', { name: 'Pub', redirect_uris: ['https://pub/cb'], scopes: ['openid'], public: true, pkce: false });
  assert.equal(r.status, 400, 'a public client cannot opt out of PKCE');
  const client = (await jpost('/admin/clients', { name: 'Pub', redirect_uris: ['https://pub/cb'], scopes: ['openid'], public: true })).body;
  assert.equal(client.public, true);
  const getCode = await signerFor('pub1', client);

  // no code_challenge -> refused at the authorization endpoint
  let c = await getCode({ pkce: false });
  assert.equal(c.login.status, 400); assert.equal(c.login.body.error, 'invalid_request');

  // PKCE without any secret -> tokens
  c = await getCode();
  r = await jpost('/token', { grant_type: 'authorization_code', code: c.code, redirect_uri: 'https://pub/cb', client_id: client.client_id, code_verifier: c.verifier });
  assert.equal(r.status, 200, 'public client + PKCE must succeed'); assert.ok(r.body.access_token);

  // userinfo: valid token -> 200; bogus token -> 401 with a Bearer challenge naming the error
  let u = await rget('/userinfo', { Authorization: `Bearer ${r.body.access_token}` });
  assert.equal(u.status, 200); assert.equal(u.body.sub, JSON.parse(Buffer.from(r.body.id_token.split('.')[1], 'base64url')).sub);
  u = await rget('/userinfo', { Authorization: 'Bearer not-a-token' });
  assert.equal(u.status, 401);
  assert.match(u.headers.get('www-authenticate') ?? '', /^Bearer error="invalid_token"/);
  u = await rget('/userinfo');
  assert.equal(u.status, 401); assert.equal(u.headers.get('www-authenticate'), 'Bearer');
});

test('discovery advertises exactly what the OP does', opt, async () => {
  const d = (await jget('/.well-known/openid-configuration', {})).body;
  assert.equal(d.issuer, BASE);
  assert.deepEqual(d.grant_types_supported, ['authorization_code']);
  assert.deepEqual(d.response_modes_supported, ['query']);
  assert.equal(d.request_parameter_supported, false);
  assert.equal(d.request_uri_parameter_supported, false);
  assert.deepEqual(d.code_challenge_methods_supported, ['S256']);
  assert.ok(d.claims_supported.includes('email_verified') && d.claims_supported.includes('auth_time'));
  assert.ok(d.token_endpoint_auth_methods_supported.includes('none'));
});

test('authorize: error codes and repeated parameters', opt, async () => {
  const client = (await jpost('/admin/clients', { name: 'Err', redirect_uris: ['https://err/cb'], scopes: ['openid'] })).body;
  const q = (o) => '/authorize?' + new URLSearchParams(o).toString();

  // unknown client / unregistered redirect_uri: answered directly, never redirected
  let r = await rget(q({ client_id: 'nope', redirect_uri: 'https://err/cb', response_type: 'code', scope: 'openid' }));
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_request');
  r = await rget(q({ client_id: client.client_id, redirect_uri: 'https://evil/cb', response_type: 'code', scope: 'openid' }));
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_request');

  // registered redirect_uri + bad response_type: redirected with error + state
  r = await rget(q({ client_id: client.client_id, redirect_uri: 'https://err/cb', response_type: 'token', scope: 'openid', state: 'xyz' }));
  assert.equal(r.status, 302);
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, 'https://err/cb');
  assert.equal(loc.searchParams.get('error'), 'unsupported_response_type');
  assert.equal(loc.searchParams.get('state'), 'xyz');

  // code_challenge without S256 method (= plain) is refused at the authorization endpoint
  r = await rget(q({ client_id: client.client_id, redirect_uri: 'https://err/cb', response_type: 'code', scope: 'openid', code_challenge: 'a'.repeat(43) }));
  assert.equal(r.status, 302);
  assert.equal(new URL(r.headers.get('location')).searchParams.get('error'), 'invalid_request');

  // a repeated parameter used to be a 500 (Array.split)
  r = await rget(q({ client_id: client.client_id, redirect_uri: 'https://err/cb', response_type: 'code' }) + '&scope=openid&scope=email');
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_request');
  r = await rget('/logout?id_token_hint=a&id_token_hint=b');
  assert.equal(r.status, 400);

  // token endpoint: missing grant_type / client_id
  let t = await rpost('/token', { code: 'x' }, { 'Content-Type': 'application/json' });
  assert.equal(t.status, 400); assert.equal(t.body.error, 'invalid_request');
  t = await rpost('/token', { grant_type: 'authorization_code', code: 'x' }, { 'Content-Type': 'application/json' });
  assert.equal(t.status, 401); assert.equal(t.body.error, 'invalid_client');
});

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const form = (path, o, extra = {}) => fetch(BASE + path, { method: 'POST', redirect: 'manual', headers: { ...FORM, ...extra }, body: new URLSearchParams(o) });

test('authorize: prompt handling and the POST form', opt, async () => {
  const client = (await jpost('/admin/clients', { name: 'Pr', redirect_uris: ['https://pr/cb'], scopes: ['openid'], pkce: false })).body;
  const base = { client_id: client.client_id, redirect_uri: 'https://pr/cb', response_type: 'code', scope: 'openid', state: 'st' };
  const q = (o) => '/authorize?' + new URLSearchParams(o).toString();

  // prompt=none: the OP has no session -> login_required, redirected with state, no UI
  let r = await rget(q({ ...base, prompt: 'none' }));
  assert.equal(r.status, 302);
  let loc = new URL(r.headers.get('location'));
  assert.equal(loc.searchParams.get('error'), 'login_required'); assert.equal(loc.searchParams.get('state'), 'st');
  r = await rget(q({ ...base, prompt: 'none login' }));
  assert.equal(new URL(r.headers.get('location')).searchParams.get('error'), 'invalid_request');
  r = await rget(q({ ...base, prompt: 'bogus' }));
  assert.equal(new URL(r.headers.get('location')).searchParams.get('error'), 'invalid_request');
  // prompt=login / consent: every sign-in is interactive anyway -> the page
  r = await fetch(BASE + q({ ...base, prompt: 'login consent' }), { redirect: 'manual' });
  assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /text\/html/);

  // POST form -> 303 to the GET form carrying the same parameters
  r = await form('/authorize', base);
  assert.equal(r.status, 303);
  loc = new URL(r.headers.get('location'), BASE);
  assert.equal(loc.pathname, '/authorize');
  assert.equal(loc.searchParams.get('client_id'), client.client_id); assert.equal(loc.searchParams.get('state'), 'st');
  // POST with an unregistered redirect_uri is refused, never redirected
  r = await form('/authorize', { ...base, redirect_uri: 'https://evil/' });
  assert.equal(r.status, 400);
});

test('logout: exact post_logout_redirect_uris, client_id, POST, legacy origin fallback', opt, async () => {
  const client = (await jpost('/admin/clients', { name: 'Lo', redirect_uris: ['https://lo/cb'], post_logout_redirect_uris: ['https://lo/bye'], scopes: ['openid'] })).body;
  assert.deepEqual(client.post_logout_redirect_uris, ['https://lo/bye']);
  const getCode = await signerFor('lo1', client);
  const c = await getCode();
  const tok = await jpost('/token', { grant_type: 'authorization_code', code: c.code, redirect_uri: 'https://lo/cb',
    client_id: client.client_id, client_secret: client.client_secret, code_verifier: c.verifier });
  assert.equal(tok.status, 200);
  const lq = (o) => '/logout?' + new URLSearchParams(o).toString();

  // verified hint + exact match -> redirect with state; the access token is revoked
  let r = await rget(lq({ id_token_hint: tok.body.id_token, post_logout_redirect_uri: 'https://lo/bye', state: 'z' }));
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), 'https://lo/bye?state=z');
  assert.equal((await rget('/userinfo', { Authorization: `Bearer ${tok.body.access_token}` })).status, 401, 'logout must revoke the access token');

  // same origin, different path -> no redirect once a list is registered
  r = await rget(lq({ id_token_hint: tok.body.id_token, post_logout_redirect_uri: 'https://lo/other' }));
  assert.equal(r.status, 200); assert.deepEqual(r.body, { logged_out: true });

  // client_id alone identifies the client; no client at all never redirects
  r = await rget(lq({ client_id: client.client_id, post_logout_redirect_uri: 'https://lo/bye' }));
  assert.equal(r.status, 302);
  r = await rget(lq({ post_logout_redirect_uri: 'https://lo/bye' }));
  assert.equal(r.status, 200);

  // POST is accepted
  r = await form('/logout', { client_id: client.client_id, post_logout_redirect_uri: 'https://lo/bye', state: 'p' });
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), 'https://lo/bye?state=p');

  // a browser gets a page, not JSON
  r = await fetch(BASE + '/logout', { headers: { Accept: 'text/html' } });
  assert.match(r.headers.get('content-type'), /text\/html/);

  // legacy client (nothing registered): the origin of a redirect_uri is accepted, anything else is not
  const legacy = (await jpost('/admin/clients', { name: 'Leg', redirect_uris: ['https://leg/cb'], scopes: ['openid'] })).body;
  r = await rget(lq({ client_id: legacy.client_id, post_logout_redirect_uri: 'https://leg/anywhere' }));
  assert.equal(r.status, 302);
  r = await rget(lq({ client_id: legacy.client_id, post_logout_redirect_uri: 'https://evil/' }));
  assert.equal(r.status, 200);

  // a hint whose audience disagrees with client_id is refused
  r = await rget(lq({ id_token_hint: tok.body.id_token, client_id: legacy.client_id }));
  assert.equal(r.status, 400);
});

test('enrollment: a rejected submit keeps the link usable; a completed one is consumed', opt, async () => {
  const { enrollToken } = await addUser('retry1');
  const good = genKey(), other = genKey();
  // wrong signature -> 400, token still valid
  let r = await submitEnroll(enrollToken, good, { signMessage: 'wrong' });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_enrollment_signature');
  // wrong kid -> 400, token still valid
  r = await submitEnroll(enrollToken, other, { kid: good.kid });
  assert.equal(r.status, 400);
  // the same link now succeeds
  r = await submitEnroll(enrollToken, good);
  assert.equal(r.status, 200, 'the link must survive rejected attempts');
  // ...and is gone afterwards
  r = await jpost('/enrollment/validate', { token: enrollToken });
  assert.equal(r.status, 404);
});

test('enrollment/invite tokens are accepted in POST bodies only, never in the query string', opt, async () => {
  const { enrollToken } = await addUser('bodytok');
  assert.equal((await jget(`/enrollment/validate?token=${enrollToken}`)).status, 404, 'GET with ?token= must not exist');
  assert.equal((await jpost('/enrollment/validate', { token: enrollToken })).status, 200);
  assert.equal((await jpost('/enrollment/validate', { token: 'short' })).status, 400);
  const client = (await jpost('/admin/clients', { name: 'BT', redirect_uris: ['https://bt/cb'], scopes: ['openid'] })).body;
  const inv = (await jpost('/admin/invite', { clients: [client.client_id], username: 'btuser', email: 'bt@f.com' })).body;
  const token = inv.invite_url.split('#token=')[1];
  assert.equal((await jget(`/signup/prefill?token=${token}`)).status, 404);
  assert.equal((await jpost('/signup/prefill', { token })).status, 200);
  const cinv = (await jpost('/admin/invite-client', { note: 'x' })).body;
  const ctoken = cinv.invite_url.split('#token=')[1];
  assert.equal((await jget(`/signup-client/prefill?token=${ctoken}`)).status, 404);
  assert.equal((await jpost('/signup-client/prefill', { token: ctoken })).status, 200);
});

test('admin users: concurrent creates with one email yield one account; null clears a field; bad input is 400 not 500', opt, async () => {
  const body = (u) => ({ username: u, name: 'X', email: 'same@dup.test', hsm_url: 'https://sw.ence.do' });
  const results = await Promise.all(['dupa', 'dupb', 'dupc'].map(u => jpost('/admin/users', body(u))));
  const created = results.filter(r => r.status === 201);
  assert.equal(created.length, 1, 'exactly one of the racing creates may win');
  assert.ok(results.filter(r => r.status === 409).length === 2);
  // the losers left no index entries behind: their usernames are free again
  for (const u of ['dupa', 'dupb', 'dupc']) {
    if (created[0].body.username === u) continue;
    assert.equal(redisCli(`hget username_index ${u}`), '');
  }
  const sub = created[0].body.sub;

  // PATCH name: null used to be a 500 from node-redis
  let r = await fetch(BASE + `/admin/users/${sub}`, { method: 'PATCH', headers: H, body: JSON.stringify({ name: null }) }).then(async x => ({ status: x.status, body: await x.json() }));
  assert.equal(r.status, 200); assert.equal(r.body.name, '');
  // claims: a nested object is refused instead of being stored as "[object Object]"
  r = await fetch(BASE + `/admin/users/${sub}/claims`, { method: 'PUT', headers: H, body: JSON.stringify({ custom_claims: { dept: { a: 1 } } }) }).then(async x => ({ status: x.status }));
  assert.equal(r.status, 400);
  // audit log with a non-numeric limit
  r = await jget('/admin/audit-log?limit=abc&offset=zz');
  assert.equal(r.status, 200); assert.equal(r.body.limit, 20);
  // client with scopes that is not an array
  r = await jpost('/admin/clients', { name: 'S', redirect_uris: ['https://s/cb'], scopes: 'openid' });
  assert.equal(r.status, 400);

  // deleting a user removes its key from /jwks.json immediately
  const { enrollToken } = await addUser('jwks1');
  const key = genKey();
  assert.equal((await submitEnroll(enrollToken, key)).status, 200);
  const subJ = (await jget('/admin/users')).body.find(u => u.username === 'jwks1').sub;
  assert.equal((await jget(`/jwks.json?kid=${key.kid}`, {})).body.keys.length, 1);
  await fetch(BASE + `/admin/users/${subJ}`, { method: 'DELETE', headers: H });
  assert.equal((await jget(`/jwks.json?kid=${key.kid}`, {})).body.keys.length, 0, 'deleted user must leave JWKS at once');
});

test('signup: key_type from the body is validated', opt, async () => {
  const client = (await jpost('/admin/clients', { name: 'KT', redirect_uris: ['https://kt/cb'], scopes: ['openid'] })).body;
  const inv = (await jpost('/admin/invite', { clients: [client.client_id], username: 'ktuser', email: 'kt@f.com' })).body;
  const token = inv.invite_url.split('#token=')[1];
  let r = await jpost('/signup/register', { token, hsm_url: 'https://sw.ence.do', key_type: 'RSA' });
  assert.equal(r.status, 400, 'an unknown key_type must be refused before the invite is consumed');
  r = await jpost('/signup/register', { token, hsm_url: 'https://sw.ence.do', key_type: 'P256' });
  assert.equal(r.status, 201);
});

test('rp-server: verifies the id_token (signature via JWKS, iss, aud, nonce) and rejects a nonce mismatch', opt, async () => {
  const RP_PORT = 9877;
  const RP = `http://localhost:${RP_PORT}`;
  const client = (await jpost('/admin/clients', { name: 'TestRP', redirect_uris: [`${RP}/callback`], scopes: ['openid', 'email', 'profile'] })).body;
  const { sub, enrollToken } = await addUser('rpuser', [client.client_id]);
  const key = genKey();
  assert.equal((await submitEnroll(enrollToken, key)).status, 200);

  // earlier tests have spent most of the 10/min /authorize/confirm budget for this IP
  { const k = redisCli("keys 'rl:confirm:*'").replace(/\n/g, ' ').trim(); if (k) redisCli('del ' + k); }
  const rp = spawn('node', ['rp-server.mjs'], { stdio: 'ignore', env: { ...process.env, OP_BASE: BASE, RP_PORT: String(RP_PORT), RP_CLIENT_ID: client.client_id, RP_CLIENT_SECRET: client.client_secret } });
  try {
    await waitPort(RP_PORT);
    // 1. RP starts the flow: read state/nonce/code_challenge from its redirect
    const start = await fetch(`${RP}/signin`, { redirect: 'manual' });
    assert.equal(start.status, 302);
    const authz = new URL(start.headers.get('location'));
    const q = Object.fromEntries(authz.searchParams);
    assert.equal(q.client_id, client.client_id);

    // 2. The user signs at the OP (software key stands in for the HSM)
    async function signWith(params) {
      const login = await jpost('/authorize/login', { sub, ...params });
      assert.equal(login.status, 200);
      const confirm = await jpost('/authorize/confirm', { session_id: login.body.session_id, signature: key.sign(login.body.signing_input) });
      return new URL(confirm.body.redirect_url);
    }
    const cb = await signWith(q);

    // 3. RP callback: exchanges the code with client_secret_basic and verifies the id_token
    const done = await fetch(cb, { redirect: 'manual' });
    assert.equal(done.status, 302, 'RP must accept a genuine id_token');
    const home = await (await fetch(`${RP}/`)).text();
    assert.match(home, /signature verified \(EdDSA/);
    assert.match(home, /rpuser@f\.com/);

    // 4. Same flow but the token is minted for a DIFFERENT nonce than the RP remembers
    await fetch(`${RP}/signout`, { redirect: 'manual' });
    const start2 = await fetch(`${RP}/signin`, { redirect: 'manual' });
    const q2 = Object.fromEntries(new URL(start2.headers.get('location')).searchParams);
    const cb2 = await signWith({ ...q2, nonce: 'not-the-rp-nonce' });
    const bad = await (await fetch(cb2, { redirect: 'manual' })).text();
    assert.match(bad, /ID Token rejected/); assert.match(bad, /nonce mismatch/);
  } finally {
    rp.kill();
  }
});

const redisCli = (args) => execSync(`redis-cli -p ${REDIS_PORT} ${args}`).toString().trim();

test('rate limiter: the counter always carries a TTL and the limit is enforced', opt, async () => {
  { const k = redisCli("keys 'rl:confirm:*'").replace(/\n/g, ' ').trim(); if (k) redisCli('del ' + k); }
  // /authorize/confirm is 10/min per IP; bogus sessions are the cheapest way to hit it
  let last;
  for (let i = 0; i < 11; i++) {
    last = await rpost('/authorize/confirm', { session_id: 'nope', signature: 'x'.repeat(86) }, { 'Content-Type': 'application/json' });
  }
  assert.equal(last.status, 429, '11th call in a minute must be rate limited');
  assert.equal(last.headers.get('retry-after'), '60');
  const keys = redisCli("keys 'rl:confirm:*'").split('\n').filter(Boolean);
  assert.ok(keys.length >= 1, 'a counter key must exist');
  for (const k of keys) {
    const ttl = Number(redisCli(`ttl "${k}"`));
    assert.ok(ttl > 0 && ttl <= 60, `counter ${k} must expire (ttl=${ttl})`);
  }
  // a counter that lost its TTL (what the old INCR-then-EXPIRE code could leave behind) is repaired on the next hit
  redisCli(`persist "${keys[0]}"`);
  assert.equal(redisCli(`ttl "${keys[0]}"`), '-1');
  await rpost('/authorize/confirm', { session_id: 'nope', signature: 'x'.repeat(86) }, { 'Content-Type': 'application/json' });
  const repaired = Number(redisCli(`ttl "${keys[0]}"`));
  assert.ok(repaired > 0 && repaired <= 60, `TTL must be restored (ttl=${repaired})`);
});

test('admin auth: failed attempts are rate limited, valid calls are not', opt, async () => {
  // a working session making many calls stays fine (the pre-existing 60/min limiter is behind auth)
  for (let i = 0; i < 12; i++) assert.equal((await jget('/admin/clients')).status, 200);
  // 10 wrong secrets -> the 11th is 429 even before the secret is looked at
  let r;
  for (let i = 0; i < 10; i++) r = await jget('/admin/clients', { Authorization: 'Bearer wrong' });
  assert.equal(r.status, 401);
  r = await rget('/admin/clients', { Authorization: 'Bearer wrong' });
  assert.equal(r.status, 429); assert.equal(r.headers.get('retry-after'), '60');
  // ...and so is the right secret from that IP until the window passes (lockout, not bypass)
  assert.equal((await jget('/admin/clients')).status, 429);
  const ttl = Number(redisCli("ttl 'rl:admin-auth-fail:" + redisCli("keys 'rl:admin-auth-fail:*'").split(':').slice(2).join(':') + "'"));
  assert.ok(ttl > 0 && ttl <= 60, `lockout counter must expire (ttl=${ttl})`);
  redisCli("del " + redisCli("keys 'rl:admin-auth-fail:*'").replace(/\n/g, ' '));   // unlock for anything after
});

test('health mirrors Redis, and the client reconnects after an outage longer than the old retry budget', opt, async () => {
  let h = await rget('/health');
  assert.equal(h.status, 200); assert.equal(h.body.redis, 'up');

  redisProc.kill();
  await sleep(1500);
  h = await rget('/health');
  assert.equal(h.status, 503, 'health must fail without Redis'); assert.equal(h.body.redis, 'down');
  assert.equal(h.body.status, 'degraded');

  // The old strategy gave up after 10 attempts (~3.5 s) and closed the client for good.
  await sleep(4500);
  redisProc = spawn('redis-server', REDIS_ARGS(), { stdio: 'ignore' });
  await waitPort(REDIS_PORT);
  for (let i = 0; i < 50 && (await rget('/health')).status !== 200; i++) await sleep(200);
  h = await rget('/health');
  assert.equal(h.status, 200, 'the app must recover once Redis is back');
  assert.equal(h.body.redis, 'up');
  // and it actually serves again -- a route that needs Redis
  assert.equal((await jget('/admin/clients')).status, 200);
});
