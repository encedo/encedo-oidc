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
