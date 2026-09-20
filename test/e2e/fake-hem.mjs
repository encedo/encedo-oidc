// A fake Encedo HEM (device + broker) plus a fake relying-party callback, for
// the browser E2E test. Speaks the subset of the device API that signin.js
// uses on the password path, verifies the SDK's eJWT for real (same code as
// hem-sdk-js/test), issues bearer tokens with the lifetime the page asked for,
// and signs with a software Ed25519 key -- so an id_token produced through
// this device verifies against the OP's JWKS like one from real hardware.
import http from 'node:http';
import crypto from 'node:crypto';

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
    return p.scope === scope;
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
      return json(res, 200, { list, total: list.length, listed: list.length });
    }
    if (path === '/api/auth/token' && req.method === 'GET') return json(res, 200, { eid: state.eid, spk: state.spkB64, jti: 'jti-' + state.log.length });
    if (path === '/api/auth/token' && req.method === 'POST') {
      const { ok, payload } = await verifyEjwt(body.auth);
      if (!ok) return json(res, 401, { error: 'bad signature' });
      const tok = { scope: payload.scope, iat: payload.iat, exp: payload.exp, sub: 'user' };
      state.issued.push(tok);
      return json(res, 200, { token: tokenJwt(tok) });
    }
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
    deviceUrl: `http://127.0.0.1:${port}`,          // hsm_url the user enters (CSP: CSP_CONNECT_EXTRA)
    brokerUrl: `http://127.0.0.1:${port}/brk`,      // ?hem_broker= for the page
    rpCallback: `http://localhost:${port}/cb`,      // redirect_uri (http allowed for localhost)
    rpBye: `http://localhost:${port}/bye`,
    close: () => server.close(),
  };
}
