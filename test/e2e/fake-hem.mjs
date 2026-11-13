// A fake Encedo HEM (device + broker) plus a fake relying-party callback, for
// the browser E2E test. Speaks the subset of the device API that signin.js
// uses on the password path, verifies the SDK's eJWT for real (same code as
// hem-sdk-js/test), issues bearer tokens with the lifetime the page asked for,
// and signs with a software Ed25519 key -- so an id_token produced through
// this device verifies against the OP's JWKS like one from real hardware.
import http from 'node:http';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

// The SDK's TEST PKI: its device key signs attestation tokens here, its chain
// is what the OP checks (ATTEST_ROOT_SHA256 = PKI.rootSha256 in the E2E env).
export const PKI = JSON.parse(readFileSync(new URL('../../hem-sdk-js/test/attest-test-pki.json', import.meta.url), 'utf8'));
const u16 = (b) => Buffer.concat([Buffer.from([b.length >> 8, b.length & 0xff]), Buffer.from(b)]);
const rawPub = (privateKey) => Buffer.from(crypto.createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url');

const b64    = (bytes) => Buffer.from(bytes).toString('base64');
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const fromB64 = (s) => new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
// A real device answers the browser SDK cross-origin, so the fake does too.
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' };
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', ...CORS }); res.end(body === undefined ? '' : JSON.stringify(body)); };
const html = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'text/html', ...CORS }); res.end(body); };
const readBody = (req) => new Promise((resolve) => { const c = []; req.on('data', (d) => c.push(d)); req.on('end', () => resolve(Buffer.concat(c))); });
const tokenJwt = (payload) => `${b64url(Buffer.from('{"alg":"HS256"}'))}.${b64url(Buffer.from(JSON.stringify(payload)))}.sig`;
const parseJwt = (t) => { try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()); } catch { return null; } };

/**
 * @param {object} opts
 * @param {Array<{kid:string,label:string,descr:string,privateKey:crypto.KeyObject}>} opts.keys  keys "on the device"
 */
export async function startFakeHem({ keys }) {
  const state = {
    keys,
    eid: 'eid-e2e',
    devKeys: await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']),
    spkB64: null,
    revoked: false,     // true = every issued token is refused (device rebooted / unplugged)
    boot: Math.floor(Date.now() / 1000) - 1000,   // "power-up" time: token upt = now - boot
    ageShift: 0,        // seconds added to every login age (an old SSO token)
    log: [],            // { path, method, body, auth }
    issued: [],         // tokens issued: { scope, iat, exp }
    callbacks: [],      // RP callbacks received: URL search params
  };
  state.spkB64 = b64(new Uint8Array(await crypto.subtle.exportKey('raw', state.devKeys.publicKey)));

  async function verifyEjwt(ejwt) {
    const [h, p, sig] = ejwt.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    const userPub = await crypto.subtle.importKey('raw', fromB64(payload.iss), 'X25519', false, []);
    const shared  = await crypto.subtle.deriveBits({ name: 'X25519', public: userPub }, state.devKeys.privateKey, 256);
    const key     = await crypto.subtle.importKey('raw', shared, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok      = await crypto.subtle.verify('HMAC', key, fromB64(sig), Buffer.from(`${h}.${p}`));
    return { ok, payload };
  }

  function bearerOk(req, scope) {
    const auth = req.headers.authorization ?? '';
    if (!auth.startsWith('Bearer ')) return false;
    const p = parseJwt(auth.slice(7));
    if (!p || state.revoked) return false;
    if (p.exp <= Math.floor(Date.now() / 1000)) return false;
    return scope === null || p.scope === scope;   // null: any valid token
  }

  // POST /api/system/config/attestation, built as the firmware builds it
  // (attestation_jwt_sign + hem_pop_sig): ES256 by the device key, PoP over
  // prefix | aud | pubkey | nonce by the attested key itself.
  async function attestationJwt(key, { nonce, aud, pop_args: popArgs }, token) {
    const devPriv = await crypto.subtle.importKey('pkcs8', Buffer.from(PKI.devicePkcs8, 'base64'), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', devPriv);
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    const header = { alg: 'ES256', typ: 'encedo-attest+jwt', kid: crypto.createHash('sha1').update(point).digest('hex'), jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
    const pub = rawPub(key.privateKey);
    const canon = Buffer.concat([u16(Buffer.from('encedo-attest-pop:v1:sig')), u16(Buffer.from(aud)), u16(pub), u16(Buffer.from(nonce, 'base64'))]);
    const iat = Math.floor(Date.now() / 1000);
    const claims = { iss: 'https://attest.encedo.com', aud, iat, exp: iat + 300, nonce, jti: crypto.randomUUID(),
      device: { hwv: 'PPA e2e', fwv: 'Encedo nGINE FW v1.3.0', blv: 'bl', assurance: 'hard', cc_mode: 0, policy: [] },
      key: { kid: key.kid, type: 'ED25519', modes: ['ExDSA'], pubkey: { primary: b64(pub) }, properties: { privatekey: true, derived: false }, created: iat, updated: iat } };
    if (popArgs) claims.pop = { signature: b64(crypto.sign(null, canon, key.privateKey)) };
    // DEV-511: the login context of the token the request carried.
    if (token) {
      claims.auth = { v: 1, iat: token.iat, age: Math.max(0, iat - token.iat) + state.ageShift, mth: 'pwd', tts: true,
        ...(token.org ? { org: token.org } : {}) };
    }
    const input = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(claims)))}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, devPriv, Buffer.from(input));
    return `${input}.${b64url(new Uint8Array(sig))}`;
  }

  async function handle(req, res) {
    const url  = new URL(req.url, 'http://x');
    const raw  = await readBody(req);
    const body = raw.length && (req.headers['content-type'] ?? '').includes('json') ? JSON.parse(raw.toString()) : null;
    const path = url.pathname;
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
    state.log.push({ path, method: req.method, body, auth: req.headers.authorization ?? null });

    // ---- device ------------------------------------------------------------
    if (path === '/api/system/checkin' && req.method === 'GET')  return json(res, 200, { check: 'c1' });
    if (path === '/api/system/checkin' && req.method === 'POST') return json(res, 200, { status: 'ok' });
    if (path === '/api/system/version') return json(res, 200, { hwv: '1', fwv: 'e2e', conf: 'PPA' });
    if (path === '/api/keymgmt/search' && req.method === 'POST') {
      // descr arrives as '^' + base64(pattern); open search (no token) like a default device
      const pattern = Buffer.from((body?.descr ?? '').replace(/^\^/, ''), 'base64').toString();
      const list = state.keys.filter(k => k.descr.startsWith(pattern)).map(k => ({
        kid: k.kid, label: k.label, type: 'ATT,PKEY,ExDSA,ED25519', descr: b64(Buffer.from(k.descr)), created: 1, updated: 1,
      }));
      // FW 1.3: `offset` skips matches, at most 15 a page; the SDK walks pages
      // until one comes back empty, so a mock ignoring offset would loop forever.
      const offset = body?.offset ?? 0, limit = Math.min(body?.limit ?? 15, 15);
      const page = list.slice(offset, offset + limit);
      return json(res, 200, { list: page, offset, total: state.keys.length, listed: page.length, deleted: 0, invalid: 0 });
    }
    if (path === '/api/auth/token' && req.method === 'GET') return json(res, 200, { eid: state.eid, spk: state.spkB64, jti: 'jti-' + state.log.length });
    if (path === '/api/auth/token' && req.method === 'POST') {
      const { ok, payload } = await verifyEjwt(body.auth);
      if (!ok) return json(res, 401, { error: 'bad signature' });
      // FW 1.3 (DEV-511): the login context goes into the token - the request
      // Origin, the device uptime at the login, the context version.
      const now = Math.floor(Date.now() / 1000);
      const tok = { scope: payload.scope, iat: payload.iat, exp: payload.exp, sub: 'U', upt: now - state.boot, v: 1,
        ...(req.headers.origin ? { org: req.headers.origin } : {}) };
      state.issued.push(tok);
      return json(res, 200, { token: tokenJwt(tok) });
    }
    if (path === '/api/keymgmt/create' && req.method === 'POST') {
      if (!bearerOk(req, 'keymgmt:gen')) return json(res, 403, undefined);
      if (body?.type !== 'ED25519' || body?.mode) return json(res, 400, undefined);   // the E2E enrolls Ed25519, no mode
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      const kid = crypto.createHash('sha1').update(rawPub(privateKey)).digest('hex').slice(0, 32);
      state.keys.push({ kid, label: body.label, descr: Buffer.from(body.descr ?? '', 'base64').toString(), privateKey });
      return json(res, 200, { kid });
    }
    if (path.startsWith('/api/keymgmt/get/') && req.method === 'GET') {
      const key = state.keys.find(k => k.kid === path.slice('/api/keymgmt/get/'.length));
      if (!key) return json(res, 404, undefined);
      if (!bearerOk(req, `keymgmt:use:${key.kid}`)) return json(res, 403, undefined);
      return json(res, 200, { type: 'ATT,PKEY,ExDSA,ED25519', label: key.label, created: 1, updated: 1, pubkey: b64(rawPub(key.privateKey)) });
    }
    if (path === '/api/system/config/attestation' && req.method === 'POST') {
      const key = state.keys.find(k => k.kid === body?.kid);
      if (!key) return json(res, 400, undefined);
      if (!bearerOk(req, `keymgmt:use:${key.kid}`)) return json(res, 403, undefined);
      if (body.pop_args && Object.keys(body.pop_args).length) return json(res, 400, undefined);   // signature PoP {} or none (sign-in)
      state.attestations = (state.attestations ?? 0) + 1;
      return json(res, 200, { attestation: await attestationJwt(key, body, parseJwt(req.headers.authorization.slice(7))) });
    }
    if (path === '/api/system/config/attestation' && req.method === 'GET') {
      if (!bearerOk(req, null)) return json(res, 401, undefined);
      return json(res, 200, { crt: PKI.device.replace(/-----[^-]+-----|\s/g, ''), genuine: 'e2e' });
    }
    // attest.encedo.com (the OP's ATTEST_URL points here)
    if (path === '/att/v1/pki') return json(res, 200, { certificates: ['root', 'attestation', 'custody'].map(k => ({ pem: PKI[k] })) });
    if (path === '/att/v1/validate' && req.method === 'POST') { state.attestValidations = (state.attestValidations ?? 0) + 1; return json(res, 200, { status: 'valid', expired: false }); }

    if (path === '/api/crypto/exdsa/sign' && req.method === 'POST') {
      const key = state.keys.find(k => k.kid === body?.kid);
      if (!key) return json(res, 404, { error: 'no such key' });
      if (!bearerOk(req, `keymgmt:use:${key.kid}`)) return json(res, 401, { error: 'unauthorized' });
      const sig = crypto.sign(null, Buffer.from(body.msg, 'base64'), key.privateKey);
      return json(res, 200, { sign: b64(sig) });
    }

    // ---- broker ------------------------------------------------------------
    if (path === '/brk/checkin') return json(res, 200, { checked: 'ok' });

    // ---- relying party -----------------------------------------------------
    if (path === '/cb')  { state.callbacks.push(Object.fromEntries(url.searchParams)); return html(res, 200, '<!doctype html><title>RP callback</title><h1 id="cb">CB</h1>'); }
    if (path === '/bye') return html(res, 200, '<!doctype html><title>RP bye</title><h1 id="bye">BYE</h1>');

    json(res, 404, { error: 'unmocked ' + req.method + ' ' + path });
  }

  const server = http.createServer((req, res) => handle(req, res).catch((e) => json(res, 500, { error: e.message })));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    state,
    port,
    deviceUrl: `http://127.0.0.1:${port}`,
    attestUrl: `http://127.0.0.1:${port}/att`,       // ATTEST_URL for the OP          // hsm_url the user enters (CSP: CSP_CONNECT_EXTRA)
    brokerUrl: `http://127.0.0.1:${port}/brk`,      // ?hem_broker= for the page
    rpCallback: `http://localhost:${port}/cb`,      // redirect_uri (http allowed for localhost)
    rpBye: `http://localhost:${port}/bye`,
    close: () => server.close(),
  };
}
