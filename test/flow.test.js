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

let redisProc, appProc;

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
  const dir = mkdtempSync(join(tmpdir(), 'oidc-test-'));
  redisProc = spawn('redis-server', ['--port', String(REDIS_PORT), '--dir', dir, '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
  await waitPort(REDIS_PORT);
  appProc = spawn('node', ['src/app.js'], {
    stdio: 'ignore',
    env: { ...process.env, REDIS_URL: `redis://127.0.0.1:${REDIS_PORT}`, PORT: String(APP_PORT),
           ISSUER: BASE, ADMIN_SECRET: SECRET, ADMIN_ALLOWED_IPS: '127.0.0.1,::1' },
  });
  await waitHealth();
});

after(() => { try { appProc?.kill(); } catch {} try { redisProc?.kill(); } catch {} });

// A failed /enrollment/submit consumes the one-time token (getDel runs before
// signature verification), so each case below gets its own fresh token.
async function submitEnroll(enrollToken, key, { kid, signMessage } = {}) {
  // Always call validate: it activates the session and generates the challenge.
  const challenge = (await jget(`/enrollment/validate?token=${enrollToken}`)).body.challenge;
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
    redirect_uri: 'https://rp/cb', client_id: client.client_id, code_verifier: verifier });

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
    const val = await jget(`/enrollment/validate?token=${reg.body.enrollment_token}`);
    const key = genKey();
    await jpost('/enrollment/submit', { token: reg.body.enrollment_token, hsm_url: 'https://sw.ence.do',
      kid: key.kid, pubkey: key.pubHex, key_type: 'Ed25519', signature: key.sign(val.body.challenge), n: nonce });
    return (await jget('/admin/users')).body.find(u => u.username === username).email_verified;
  }

  assert.equal(await signupEnroll('noemail', false), 'false', 'no nonce -> not verified');
  assert.equal(await signupEnroll('yesemail', true),  'true',  'invite nonce -> verified');
});
