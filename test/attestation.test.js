// Key attestation at enrollment (HEM firmware 1.3): the server checks the
// attestation JWT the page got from hem.attest(), the device chain against a
// pinned root and attest.encedo.com's verdict, and applies the policy.
//
// The tokens are built the way the firmware builds them (api_system.c
// attestation_jwt_sign, hem_pop_sig), signed by the device key of the SDK's
// TEST PKI (hem-sdk-js/test/attest-test-pki.json); attest.encedo.com is faked
// in this process. Spawns its own redis-server + app; skips without Redis.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';

const REDIS_PORT = 6397;
const APP_PORT   = 3397;
const BASE       = `http://127.0.0.1:${APP_PORT}`;
const SECRET     = 'test-secret';
const PKI = JSON.parse(readFileSync(new URL('../hem-sdk-js/test/attest-test-pki.json', import.meta.url), 'utf8'));

let hasRedis = true;
try { execSync('command -v redis-server', { stdio: 'ignore' }); } catch { hasRedis = false; }
const opt = hasRedis ? {} : { skip: 'redis-server not installed' };

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const b64   = (b) => Buffer.from(b).toString('base64');
const b64url = (b) => Buffer.from(b).toString('base64url');
const u16   = (b) => Buffer.concat([Buffer.from([b.length >> 8, b.length & 0xff]), Buffer.from(b)]);

async function waitPort(port) {
  for (let i = 0; i < 50; i++) {
    const up = await new Promise(res => { const s = net.connect(port, '127.0.0.1'); s.on('connect', () => { s.destroy(); res(true); }); s.on('error', () => res(false)); });
    if (up) return;
    await sleep(100);
  }
  throw new Error(`port ${port} never came up`);
}

const H = { Authorization: `Bearer ${SECRET}`, 'Content-Type': 'application/json' };
const call = (method, p, b) => fetch(BASE + p, { method, headers: H, body: b && JSON.stringify(b) })
  .then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));

// --- fake attest.encedo.com ----------------------------------------------------
const fakeAttest = { verdict: 'valid', validateCalls: [] };
let attestServer;

function startFakeAttest() {
  attestServer = http.createServer((req, res) => {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', () => {
      const send = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (req.method === 'GET' && req.url === '/v1/pki') {
        return send(200, { certificates: ['root', 'attestation', 'custody'].map(k => ({ pem: PKI[k] })) });
      }
      if (req.method === 'POST' && req.url === '/v1/validate') {
        fakeAttest.validateCalls.push(JSON.parse(raw));
        return send(200, { status: fakeAttest.verdict, expired: false });
      }
      send(404, {});
    });
  });
  return new Promise(r => attestServer.listen(0, '127.0.0.1', () => r(attestServer.address().port)));
}

// --- a software HEM key and its attestation token ------------------------------
function genKey(type = 'Ed25519') {
  if (type === 'Ed25519') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    return { type, hemType: 'ED25519', pub: raw, pubHex: raw.toString('hex'),
      kid: crypto.createHash('sha1').update(raw).digest('hex').slice(0, 32),
      sign: (m) => crypto.sign(null, Buffer.from(m), privateKey) };
  }
  // P-256: the HEM gives the compressed point, signs raw r||s
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pub = crypto.ECDH.convertKey(publicKey.export({ format: 'der', type: 'spki' }).subarray(-65), 'prime256v1', undefined, undefined, 'compressed');
  return { type: 'P256', hemType: 'SECP256R1', pub, pubHex: pub.toString('hex'),
    kid: crypto.createHash('sha1').update(pub).digest('hex').slice(0, 32),
    sign: (m) => crypto.sign('sha256', Buffer.from(m), { key: privateKey, dsaEncoding: 'ieee-p1363' }) };
}

/** What the HEM answers to POST /api/system/config/attestation for `key`. */
async function attestToken(key, { nonce, aud }, { assurance = 'hard', popKey = key, nonceForPop = nonce, attested = key, properties = { privatekey: true, derived: false } } = {}) {
  const priv = await crypto.subtle.importKey('pkcs8', Buffer.from(PKI.devicePkcs8, 'base64'), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const header = { alg: 'ES256', typ: 'encedo-attest+jwt', kid: crypto.createHash('sha1').update(point).digest('hex'),
    jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
  const canon = Buffer.concat([u16(Buffer.from('encedo-attest-pop:v1:sig')), u16(Buffer.from(aud)), u16(attested.pub),
    u16(Buffer.from(nonceForPop, 'base64'))]);
  const iat = Math.floor(Date.now() / 1000);
  const body = { iss: 'https://attest.encedo.com', aud, iat, exp: iat + 300, nonce, jti: crypto.randomUUID(),
    device: { hwv: 'PPA rev 2.2', fwv: 'Encedo nGINE FW v1.3.0', blv: 'bl', assurance, cc_mode: 0, policy: [] },
    key: { kid: key.kid, type: attested.hemType, modes: ['ExDSA'], pubkey: { primary: b64(attested.pub) }, properties, created: iat, updated: iat },
    pop: { signature: b64(popKey.sign(canon)) } };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(body))}`;
  const sig = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, Buffer.from(input)));
  return `${input}.${b64url(sig)}`;
}
const CRT = PKI.device.replace(/-----[^-]+-----|\s/g, '');   // base64 DER, as getAttestation() gives it

// --- app ------------------------------------------------------------------------
let redisProc, appProc;
before(async () => {
  if (!hasRedis) return;
  const attestPort = await startFakeAttest();
  redisProc = spawn('redis-server', ['--port', String(REDIS_PORT), '--dir', mkdtempSync(join(tmpdir(), 'oidc-att-')), '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
  await waitPort(REDIS_PORT);
  appProc = spawn('node', ['src/app.js'], {
    stdio: 'ignore',
    env: { ...process.env, REDIS_URL: `redis://127.0.0.1:${REDIS_PORT}`, PORT: String(APP_PORT), ISSUER: BASE,
      ADMIN_SECRET: SECRET, ADMIN_ALLOWED_IPS: '127.0.0.1,::1',
      ATTEST_URL: `http://127.0.0.1:${attestPort}`, ATTEST_ROOT_SHA256: PKI.rootSha256, ATTEST_POLICY: '' },
  });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/health')).ok) break; } catch {} await sleep(100); }
});
after(() => { try { appProc?.kill(); } catch {} try { redisProc?.kill(); } catch {} attestServer?.close(); });

let n = 0;
async function addUser(policy, key_type = 'Ed25519') {
  const r = await call('POST', '/admin/users', { username: `att${++n}`, name: 'A T', email: `att${n}@f.com`, hsm_url: 'https://sw.ence.do', key_type });
  const sub = r.body.sub;
  if (policy !== undefined) assert.equal((await call('PATCH', `/admin/users/${sub}`, { attest_policy: policy })).status, 200);
  return { sub, token: r.body.enrollment_url.split('#token=')[1].split('&')[0] };
}

/** validate + submit; `attest(chal)` returns { attestation, crt } or nothing. */
async function enroll(user, key, attest = null) {
  const v = await call('POST', '/enrollment/validate', { token: user.token });
  assert.equal(v.status, 200);
  assert.equal(v.body.attest.aud, BASE, 'aud = the issuer');
  assert.equal(Buffer.from(v.body.attest.nonce, 'base64').length, 32);
  const extra = attest ? await attest(v.body.attest) : {};
  return call('POST', '/enrollment/submit', { token: user.token, hsm_url: 'https://sw.ence.do', kid: key.kid,
    pubkey: key.pubHex, key_type: key.type, signature: b64url(key.sign(v.body.challenge)), ...extra });
}
const getUser = async (sub) => (await call('GET', `/admin/users/${sub}`)).body;

// --- tests ----------------------------------------------------------------------
test('advisory (default): no attestation still enrolls, recorded as absent', opt, async () => {
  const u = await addUser(); const k = genKey();
  const r = await enroll(u, k);
  assert.equal(r.status, 200);
  assert.equal(r.body.attest_status, 'absent');
  const rec = await getUser(u.sub);
  assert.equal(rec.attest_status, 'absent'); assert.equal(rec.hw_attested, 'false');
});

test('PPA (hard): token + PoP + chain to the pinned root + online valid = verified', opt, async () => {
  for (const type of ['Ed25519', 'P256']) {
    fakeAttest.validateCalls.length = 0;
    const u = await addUser(undefined, type); const k = genKey(type);
    const r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c), crt: CRT }));
    assert.equal(r.status, 200, `${type}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.attest_status, 'verified', type);
    assert.equal(r.body.hw_attested, 'true');
    assert.equal(fakeAttest.validateCalls.length, 1, 'asked attest.encedo.com once');
    const rec = await getUser(u.sub);
    assert.equal(rec.attest_assurance, 'hard'); assert.equal(rec.attest_online, 'valid');
    assert.match(rec.attest_jwt, /^ey[\w-]+\.[\w-]+\.[\w-]+$/, 'the signed evidence is kept');
    assert.equal(rec.hsm_crt, CRT);
  }
});

test('EPA (soft): the token alone, never sent online, token_only and not hw_attested', opt, async () => {
  fakeAttest.validateCalls.length = 0;
  const u = await addUser(); const k = genKey();
  const r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c, { assurance: 'soft' }) }));
  assert.equal(r.status, 200);
  assert.equal(r.body.attest_status, 'token_only'); assert.equal(r.body.hw_attested, 'false');
  assert.equal(r.body.attest_assurance, 'soft');
  assert.equal(fakeAttest.validateCalls.length, 0);
});

test('failures are recorded with a reason (advisory lets them through)', opt, async () => {
  const cases = [
    ['PoP over another nonce (replay)', (k, c) => attestToken(k, c, { nonceForPop: b64(crypto.randomBytes(32)) }), /pop/],
    ['another key attested',            (k, c) => { const o = genKey(); return attestToken(k, c, { attested: o, popKey: o }); }, /pubkey_mismatch/],
    ['imported, not generated in HEM',  (k, c) => attestToken(k, c, { properties: { privatekey: true, derived: true } }), /key_not_generated_in_hem/],
    ['token for another challenge',     (k)    => attestToken(k, { nonce: b64(crypto.randomBytes(32)), aud: BASE }), /nonce/],
    ['token for another verifier',      (k, c) => attestToken(k, { ...c, aud: 'https://evil.example' }), /aud/],
  ];
  for (const [name, make, reason] of cases) {
    const u = await addUser(); const k = genKey();
    const r = await enroll(u, k, async (c) => ({ attestation: await make(k, c), crt: CRT }));
    assert.equal(r.status, 200, name);
    assert.equal(r.body.attest_status, 'failed', name);
    assert.match((await getUser(u.sub)).attest_reason, reason, name);
  }
  // online says invalid
  fakeAttest.verdict = 'invalid';
  try {
    const u = await addUser(); const k = genKey();
    const r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c), crt: CRT }));
    assert.equal(r.body.attest_status, 'failed');
    assert.equal((await getUser(u.sub)).attest_reason, 'online_invalid');
  } finally { fakeAttest.verdict = 'valid'; }
});

test('policy require (per user): refuses without a valid token, the link survives, EPA passes', opt, async () => {
  const u = await addUser('require'); const k = genKey();
  let r = await enroll(u, k);
  assert.equal(r.status, 400); assert.equal(r.body.error, 'attestation_required');
  r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c, { nonceForPop: b64(crypto.randomBytes(32)) }) }));
  assert.equal(r.status, 400, 'a failed PoP is refused too');
  r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c, { assurance: 'soft' }) }));
  assert.equal(r.status, 200, 'the same link, now with an EPA token');
  assert.equal(r.body.attest_status, 'token_only');
});

test('policy require_hard: EPA and a PPA without its certificate are refused, a chained PPA passes', opt, async () => {
  const u = await addUser('require_hard'); const k = genKey();
  let r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c, { assurance: 'soft' }) }));
  assert.equal(r.status, 400); assert.equal(r.body.error, 'attestation_required');
  r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c) }));
  assert.equal(r.status, 400, 'no crt: the device origin is not proven');
  r = await enroll(u, k, async (c) => ({ attestation: await attestToken(k, c), crt: CRT }));
  assert.equal(r.status, 200); assert.equal(r.body.attest_status, 'verified');
});

test('admin: attest_policy is validated and can be reset to the server default', opt, async () => {
  const u = await addUser();
  assert.equal((await call('PATCH', `/admin/users/${u.sub}`, { attest_policy: 'strict' })).status, 400);
  assert.equal((await call('PATCH', `/admin/users/${u.sub}`, { attest_policy: 'require_hard' })).status, 200);
  assert.equal((await getUser(u.sub)).attest_policy, 'require_hard');
  assert.equal((await call('PATCH', `/admin/users/${u.sub}`, { attest_policy: '' })).status, 200);
  assert.equal((await getUser(u.sub)).attest_policy, '');
});

// --- re-attestation of the enrolled key (F4) ------------------------------------
// This file enrolls more than the per-IP limit allows in a minute: start each
// re-attestation test with fresh counters (the test owns this Redis).
function clearRateLimits() {
  execSync(`redis-cli -p ${REDIS_PORT} --scan --pattern 'rl:*' | xargs -r redis-cli -p ${REDIS_PORT} del`, { stdio: 'ignore', shell: '/bin/sh' });
}
async function reattestLink(sub) {
  clearRateLimits();
  const r = await call('POST', `/admin/users/${sub}/reattest`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body.reattest_url.split('#token=')[1];
}
const reValidate = (token) => call('POST', '/reattest/validate', { token });
const reSubmit   = (token, body) => call('POST', '/reattest/submit', { token, ...body });

test('re-attestation: an enrolled key without attestation becomes verified, same kid and pubkey', opt, async () => {
  for (const type of ['Ed25519', 'P256']) {
    const u = await addUser(undefined, type); const k = genKey(type);
    assert.equal((await enroll(u, k)).body.attest_status, 'absent');
    const before = await getUser(u.sub);

    const token = await reattestLink(u.sub);
    assert.equal((await getUser(u.sub)).reattest_token, undefined, 'the token is never exposed');
    const v = await reValidate(token);
    assert.equal(v.status, 200);
    assert.equal(v.body.kid, k.kid); assert.equal(v.body.attest.aud, BASE);
    const r = await reSubmit(token, { attestation: await attestToken(k, v.body.attest), crt: CRT });
    assert.equal(r.status, 200, `${type}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.attest_status, 'verified');

    const after = await getUser(u.sub);
    assert.equal(after.kid, before.kid); assert.equal(after.pubkey, before.pubkey);
    assert.equal(after.attest_status, 'verified'); assert.equal(after.hw_attested, 'true');
    assert.match(after.attest_jwt, /^ey/);
    assert.equal((await reValidate(token)).status, 404, 'one-time link');
  }
});

test('re-attestation: a failed check keeps the link; a wrong key or a replay does not pass', opt, async () => {
  const u = await addUser(); const k = genKey();
  await enroll(u, k);
  const token = await reattestLink(u.sub);
  const v = await reValidate(token);
  const other = genKey();
  const bad = await reSubmit(token, { attestation: await attestToken(other, v.body.attest), crt: CRT });
  assert.equal(bad.status, 400); assert.equal(bad.body.error, 'attestation_failed');
  const replay = await reSubmit(token, { attestation: await attestToken(k, { nonce: b64(crypto.randomBytes(32)), aud: BASE }), crt: CRT });
  assert.equal(replay.status, 400);
  assert.equal((await reSubmit(token, {})).status, 400, 'no attestation');
  assert.equal((await getUser(u.sub)).attest_status, 'absent', 'record untouched');
  const v2 = await reValidate(token);
  assert.equal(v2.status, 200, 'link still valid');
  assert.equal(v2.body.attest.nonce, v.body.attest.nonce, 'same challenge');
  assert.equal((await reSubmit(token, { attestation: await attestToken(k, v2.body.attest), crt: CRT })).status, 200);
});

test('re-attestation: a re-enrollment voids the link; no link without an enrolled key', opt, async () => {
  const u = await addUser(); const k = genKey();
  await enroll(u, k);
  const token = await reattestLink(u.sub);
  const again = await call('POST', `/admin/users/${u.sub}/enrollment`, {});
  const re = await enroll({ sub: u.sub, token: again.body.enrollment_url.split('#token=')[1] }, genKey());
  assert.equal(re.status, 200, `re-enrollment: ${JSON.stringify(re.body)}`);
  const v = await reValidate(token);
  assert.equal(v.status, 409); assert.equal(v.body.error, 'key_changed');

  const fresh = await addUser();
  const r = await call('POST', `/admin/users/${fresh.sub}/reattest`);
  assert.equal(r.status, 409); assert.equal(r.body.error, 'not_enrolled');

  const t1 = await reattestLink(u.sub), t2 = await reattestLink(u.sub);
  assert.equal((await reValidate(t1)).status, 404, 'a new link replaces the old one');
  assert.equal((await reValidate(t2)).status, 200);
  const mail = await call('POST', `/admin/users/${u.sub}/reattest/send-email`);
  assert.equal(mail.status, 409); assert.equal(mail.body.error, 'mail_disabled', 'no SMTP in this test');
});

// --- sign-in: the HEM login context (FW 1.3, DEV-511) ----------------------------
// The page asks the HEM for an attestation over the /authorize/login challenge
// with the token it signs with; the device adds the `auth` block. Levels and
// refusals: src/services/loa.js and /authorize/attest in src/routes/oidc.js.

/** An attestation at sign-in: device only plus the key block, no PoP, with `auth`. */
async function loginAttestation(key, { nonce, aud }, auth, { otherDevice = false } = {}) {
  const priv = otherDevice
    ? (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])).privateKey
    : await crypto.subtle.importKey('pkcs8', Buffer.from(PKI.devicePkcs8, 'base64'), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const header = { alg: 'ES256', typ: 'encedo-attest+jwt', kid: crypto.createHash('sha1').update(point).digest('hex'),
    jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
  const iat = Math.floor(Date.now() / 1000);
  const body = { iss: 'https://attest.encedo.com', aud, iat, exp: iat + 300, nonce, jti: crypto.randomUUID(),
    device: { hwv: 'PPA rev 2.2', fwv: 'Encedo nGINE FW v1.3.0', blv: 'bl', assurance: 'hard', cc_mode: 0, policy: [] },
    key: { kid: key.kid, type: key.hemType, modes: ['ExDSA'], pubkey: { primary: b64(key.pub) }, properties: { privatekey: true, derived: false }, created: iat, updated: iat },
    ...(auth ? { auth: { v: 1, iat: iat - (auth.age ?? 0), tts: true, ...auth } } : {}) };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(body))}`;
  const sig = Buffer.from(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, Buffer.from(input)));
  return `${input}.${b64url(sig)}`;
}
const jwtBody = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());
const AKID = '00112233445566778899aabbccddeeff';

let loaClient;
async function loaSetup({ attested = true } = {}) {
  clearRateLimits();
  if (!loaClient) loaClient = (await call('POST', '/admin/clients', { name: 'LoA RP', redirect_uris: ['https://loa/cb'], scopes: ['openid'], pkce: false, allow_any_user: true })).body;
  const key = genKey();
  const user = await addUser();
  const r = await enroll(user, key, attested ? async (chal) => ({ attestation: await attestToken(key, chal), crt: CRT }) : null);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { key, sub: user.sub };
}
const loaLogin = (sub, extra = {}) => call('POST', '/authorize/login', { sub, client_id: loaClient.client_id, redirect_uri: 'https://loa/cb',
  response_type: 'code', scope: 'openid', nonce: 'n', ...extra });
const loaAttest = (login, attestation) => call('POST', '/authorize/attest', { session_id: login.body.session_id, ...(attestation ? { attestation } : {}) });

test('sign-in context: passphrase on an attested PPA from this origin is level 3; the ID Token carries it', opt, async () => {
  const { key, sub } = await loaSetup();
  assert.equal((await getUser(sub)).attest_status, 'verified');
  const login = await loaLogin(sub);
  assert.equal(login.status, 200, JSON.stringify(login.body));
  assert.equal(login.body.signing_input, undefined, 'nothing to sign before the login context');
  assert.deepEqual(login.body.loa, { required: 0 });
  assert.equal(login.body.attest.kid, key.kid);
  assert.equal(login.body.claims.sub, sub);

  const att = await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 3, org: BASE });
  const ctx = await loaAttest(login, att);
  assert.equal(ctx.status, 200, JSON.stringify(ctx.body));
  const p = jwtBody(ctx.body.signing_input);
  assert.equal(p.acr, 'urn:encedo:loa:3');
  assert.deepEqual(p.amr, ['hwk', 'pwd', 'mfa']);
  const now = Math.floor(Date.now() / 1000);
  assert.ok(Math.abs(p.auth_time - (now - 3)) <= 2, `auth_time from the device age: ${p.auth_time} vs ${now - 3}`);
  assert.equal((await loaAttest(login, att)).status, 400, 'one login context per session');

  const conf = await call('POST', '/authorize/confirm', { session_id: login.body.session_id, signature: b64url(key.sign(ctx.body.signing_input)) });
  assert.equal(conf.status, 200, JSON.stringify(conf.body));
  const code = new URL(conf.body.redirect_url).searchParams.get('code');
  const tok = await call('POST', '/token', { grant_type: 'authorization_code', code, redirect_uri: 'https://loa/cb', client_id: loaClient.client_id, client_secret: loaClient.client_secret });
  assert.equal(tok.status, 200);
  assert.equal(jwtBody(tok.body.id_token).acr, 'urn:encedo:loa:3');

  const disco = (await call('GET', '/.well-known/openid-configuration')).body;
  assert.deepEqual(disco.acr_values_supported, ['urn:encedo:loa:0', 'urn:encedo:loa:1', 'urn:encedo:loa:2', 'urn:encedo:loa:3']);
  assert.ok(disco.claims_supported.includes('acr'));
});

test('sign-in context: a login started on another site is refused, and the session is gone', opt, async () => {
  const { key, sub } = await loaSetup();
  const login = await loaLogin(sub);
  const r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 1, org: 'https://evil.example' }));
  assert.equal(r.status, 403); assert.equal(r.body.error, 'origin_mismatch');
  assert.match(r.body.error_description, /evil\.example/);
  const conf = await call('POST', '/authorize/confirm', { session_id: login.body.session_id, signature: b64url(key.sign('x')) });
  assert.equal(conf.status, 400, 'nothing left to confirm');
});

test('sign-in context: phone levels from actx (uvm, lock, hw) and the required level', opt, async () => {
  const { key, sub } = await loaSetup();
  const level = async (actx, extra = {}) => {
    const login = await loaLogin(sub, extra);
    const r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'ext', age: 5, akid: AKID, org: BASE, actx }));
    return r.status === 200 ? jwtBody(r.body.signing_input).acr.slice(-1) : `${r.status}:${r.body.error}:${r.body.level}`;
  };
  assert.equal(await level({ v: 1, lock: 'none', uvm: 'none', hw: 'tee' }), '1', 'approved, nobody verified');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'none', hw: 'tee' }), '2', 'the app is locked with a PIN');
  assert.equal(await level({ v: 1, lock: 'none', uvm: 'pin', hw: 'sw' }), '2', 'PIN at this approval, but the app key in software');
  assert.equal(await level({ v: 1, lock: 'none', uvm: 'pin', hw: 'kc' }), '2', 'iOS keychain is not hardware here');
  assert.equal(await level({ v: 1, lock: 'bio+pin', uvm: 'bio', hw: 'tee' }), '3');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'pin', hw: 'sb' }), '3');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'bio', hw: 'se' }), '3');

  // required: max(client, user, acr_values)
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'none', hw: 'tee' }, { acr_values: 'urn:encedo:loa:3' }), '403:insufficient_assurance:2');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'none', hw: 'tee' }, { acr_values: 'urn:encedo:loa:2 urn:encedo:loa:3' }), '2', 'the lowest listed value');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'none', hw: 'tee' }, { acr_values: 'urn:other:gold' }), '2', 'unknown values ignored');
  assert.equal((await call('PATCH', `/admin/users/${sub}`, { min_loa: 3 })).status, 200);
  assert.equal((await getUser(sub)).min_loa, 3);
  assert.equal((await loaLogin(sub)).body.loa.required, 3, 'the user is stricter than the client');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'none', hw: 'tee' }), '403:insufficient_assurance:2');
  assert.equal(await level({ v: 1, lock: 'pin', uvm: 'bio', hw: 'tee' }), '3');
  assert.equal((await call('PATCH', `/admin/users/${sub}`, { min_loa: 9 })).status, 400);
  await call('PATCH', `/admin/users/${sub}`, { min_loa: 0 });
});

test('sign-in context: no attestation, another device, an unattested enrollment = level 0', opt, async () => {
  const { key, sub } = await loaSetup();
  let login = await loaLogin(sub);
  let r = await loaAttest(login, null);
  assert.equal(r.status, 200); assert.equal(jwtBody(r.body.signing_input).acr, 'urn:encedo:loa:0');
  assert.deepEqual(jwtBody(r.body.signing_input).amr, ['hwk']);

  login = await loaLogin(sub);
  r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 1, org: BASE }, { otherDevice: true }));
  assert.equal(r.status, 200); assert.equal(jwtBody(r.body.signing_input).acr, 'urn:encedo:loa:0', 'not the device attested at enrollment');

  login = await loaLogin(sub);
  const otherKey = { ...genKey(), kid: key.kid };   // the enrolled kid, another public key
  r = await loaAttest(login, await loginAttestation(otherKey, login.body.attest, { mth: 'pwd', age: 1, org: BASE }));
  assert.equal(r.status, 200); assert.equal(jwtBody(r.body.signing_input).acr, 'urn:encedo:loa:0', 'the attested key is not the enrolled one');

  login = await loaLogin(sub);
  r = await loaAttest(login, await loginAttestation(key, { ...login.body.attest, nonce: b64(crypto.randomBytes(32)) }, { mth: 'pwd', age: 1, org: BASE }));
  assert.equal(jwtBody(r.body.signing_input).acr, 'urn:encedo:loa:0', 'another challenge');

  const plain = await loaSetup({ attested: false });
  login = await loaLogin(plain.sub);
  r = await loaAttest(login, await loginAttestation(plain.key, login.body.attest, { mth: 'pwd', age: 1, org: BASE }));
  assert.equal(jwtBody(r.body.signing_input).acr, 'urn:encedo:loa:0', 'no device on record to compare with');

  // the client asks for more: level 0 is refused
  assert.equal((await call('PATCH', `/admin/clients/${loaClient.client_id}`, { min_loa: 1 })).status, 200);
  login = await loaLogin(sub);
  assert.equal(login.body.loa.required, 1);
  r = await loaAttest(login, null);
  assert.equal(r.status, 403); assert.equal(r.body.error, 'insufficient_assurance'); assert.equal(r.body.level, 0);
  login = await loaLogin(sub);
  r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 1, org: BASE }, { otherDevice: true }));
  assert.equal(r.status, 403); assert.match(r.body.error_description, /re-attestation link/, 'another device: the page says what fixes it');
  login = await loaLogin(sub);
  r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 1 }));
  assert.equal(jwtBody(r.body.signing_input).acr, 'urn:encedo:loa:1', 'no Origin at the HEM login: at most level 1');
  assert.equal((await call('PATCH', `/admin/clients/${loaClient.client_id}`, { min_loa: '4' })).status, 400);
  await call('PATCH', `/admin/clients/${loaClient.client_id}`, { min_loa: 0 });
});

test('sign-in context: max_age and a kept SSO session are judged by the device age', opt, async () => {
  const { key, sub } = await loaSetup();
  let login = await loaLogin(sub, { max_age: '60' });
  let r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 600, org: BASE }));
  assert.equal(r.status, 409); assert.equal(r.body.error, 'sso_stale');

  // the page says 10 minutes ago, the device says 9 hours: the device wins
  const now = Math.floor(Date.now() / 1000);
  login = await loaLogin(sub, { sso_iat: String(now - 600) });
  assert.equal(login.body.sso.used, true);
  r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 9 * 3600, org: BASE }));
  assert.equal(r.status, 409); assert.equal(r.body.error, 'sso_stale');

  login = await loaLogin(sub, { sso_iat: String(now - 600) });
  r = await loaAttest(login, await loginAttestation(key, login.body.attest, { mth: 'pwd', age: 620, org: BASE }));
  assert.equal(r.status, 200);
  const p = jwtBody(r.body.signing_input);
  assert.deepEqual(p.amr, ['hwk', 'pwd', 'mfa', 'sso']);
  assert.ok(Math.abs(p.auth_time - (now - 620)) <= 3);
});
