// -------------------------------------------------------------
//  Encedo Test RP -- server-side OIDC flow
//  Port: 9876  |  Redirect: http://localhost:9876/callback
//  Usage: node rp-server.mjs
// -------------------------------------------------------------
import http          from 'http';
import crypto        from 'crypto';
import { URLSearchParams } from 'url';

const OP_BASE    = process.env.OP_BASE    || 'http://localhost:3000';
const CLIENT_ID  = process.env.RP_CLIENT_ID  || '';
const CLIENT_SECRET = process.env.RP_CLIENT_SECRET || '';   // empty = registered as a public client (PKCE only)
const RP_PORT    = process.env.RP_PORT    || 9876;
const REDIRECT   = `http://localhost:${RP_PORT}/callback`;

if (!CLIENT_ID) { console.error('ERROR: RP_CLIENT_ID not set'); process.exit(1); }

// -- In-memory session (one user at a time -- dev only) ---------
let pending = null;   // { verifier, state, nonce }
let session = null;   // { access_token, id_token, payload }

// -- PKCE ------------------------------------------------------
function randomB64url(n) {
  return crypto.randomBytes(n).toString('base64url');
}
function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// -- ID Token validation (OIDC Core s.3.1.3.7) -----------------
// A test RP that only decoded the token would stay green through a broken
// DER->P1363 conversion, a wrong alg/kid in JWKS or a missing nonce. This RP
// verifies what a real one must: signature via the OP's jwks_uri (the key
// named by the header kid), iss against discovery, aud, exp/iat, nonce.
const ES_HASH = { ES256: 'sha256', ES384: 'sha384', ES512: 'sha512' };
const b64json = s => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

async function verifyIdToken(idToken, expectedNonce) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('id_token is not a compact JWS');
  const [h, p, sig] = parts;
  const header = b64json(h), payload = b64json(p);

  const disc = await (await fetch(`${OP_BASE}/.well-known/openid-configuration`)).json();
  if (payload.iss !== disc.issuer) throw new Error(`iss mismatch: ${payload.iss} != ${disc.issuer}`);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(CLIENT_ID)) throw new Error(`aud does not contain this client: ${aud}`);
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now - 60) throw new Error('id_token expired');
  if (typeof payload.iat !== 'number' || payload.iat > now + 60)  throw new Error('iat is in the future');
  if (payload.nonce !== expectedNonce) throw new Error('nonce mismatch');

  const jwks = await (await fetch(disc.jwks_uri, { cache: 'no-store' })).json();
  const jwk  = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error(`no key ${header.kid} in ${disc.jwks_uri}`);
  const key   = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const data  = Buffer.from(`${h}.${p}`);
  const sigB  = Buffer.from(sig, 'base64url');
  const ok = header.alg === 'EdDSA'
    ? crypto.verify(null, data, key, sigB)
    : ES_HASH[header.alg]
      ? crypto.verify(ES_HASH[header.alg], data, { key, dsaEncoding: 'ieee-p1363' }, sigB)
      : false;
  if (!ok) throw new Error(`signature invalid (alg ${header.alg}, kid ${header.kid})`);
  return { header, payload };
}

// -- HTML escaping: claims and OP error strings are untrusted -----
const esc = v => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// -- Tiny HTML helper -----------------------------------------
const CSS = `
  body{font-family:system-ui,sans-serif;background:#0a0c0f;color:#D8C8F8;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#0f1318;border:1px solid #1e2730;border-radius:14px;padding:36px 40px;max-width:520px;width:100%}
  h2{color:#F2EEFF;margin:0 0 24px;font-size:18px}
  a.btn,button{display:inline-block;background:linear-gradient(135deg,#A060FF,#5C28CC);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;font-size:13px;border:none;cursor:pointer;width:100%;text-align:center}
  pre{background:#141920;border:1px solid #1e2730;border-radius:8px;padding:14px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#C4A8FF;line-height:1.7}
  .label{font-size:9px;letter-spacing:.2em;color:#4a5a6a;text-transform:uppercase;margin:20px 0 8px}
  .row{display:flex;justify-content:space-between;font-size:11px;font-family:monospace;margin-bottom:6px}
  .k{color:#4a5a6a}.v{color:#D8C8F8;word-break:break-all;text-align:right;max-width:70%}
  .v.green{color:#34D89A} .err{color:#FF4D72;font-size:12px;margin-top:16px}
`;

function page(body) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>${CSS}</style></head><body>${body}</body></html>`;
}

// -- Routes ---------------------------------------------------
async function router(req, res) {
  const url = new URL(req.url, `http://localhost:${RP_PORT}`);

  // GET / -- home
  if (url.pathname === '/' && req.method === 'GET') {
    if (session) {
      const p = session.payload;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`
        <div class="card">
          <h2>Logged in</h2>
          <div class="row"><span class="k">name</span>  <span class="v">${esc(p.name||'--')}</span></div>
          <div class="row"><span class="k">email</span> <span class="v">${esc(p.email||'--')}</span></div>
          <div class="row"><span class="k">sub</span>   <span class="v">${esc(p.sub||'--')}</span></div>
          <div class="row"><span class="k">id_token</span><span class="v green">signature verified (${esc(session.header.alg)}, kid ${esc(String(session.header.kid).slice(0,8))}…)</span></div>
          <div class="row"><span class="k">access_token</span><span class="v green">${esc(session.access_token.slice(0,20))}...</span></div>
          <div class="label">id_token payload</div>
          <pre>${esc(JSON.stringify(p, null, 2))}</pre>
          <div class="label">id_token header</div>
          <pre>${esc(JSON.stringify(session.header, null, 2))}</pre>
          <br><a class="btn" href="/signout">Sign out</a>
        </div>`));
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(page(`
      <div class="card">
        <h2>Encedo Test RP</h2>
        <div class="row"><span class="k">OP</span>         <span class="v">${esc(OP_BASE)}</span></div>
        <div class="row"><span class="k">client_id</span>  <span class="v">${esc(CLIENT_ID)}</span></div>
        <div class="row"><span class="k">auth</span>       <span class="v">${CLIENT_SECRET ? 'client_secret_basic + PKCE' : 'public (PKCE only)'}</span></div>
        <div class="row"><span class="k">redirect_uri</span><span class="v">${REDIRECT}</span></div>
        <div class="row"><span class="k">pkce</span>       <span class="v green">S256 ok</span></div>
        <br><a class="btn" href="/signin">Sign in with Encedo</a>
      </div>`));
  }

  // GET /signin -- generuj PKCE, redirect do OP
  if (url.pathname === '/signin' && req.method === 'GET') {
    const verifier = randomB64url(32);
    const state    = randomB64url(12);
    const nonce    = randomB64url(12);

    pending = { verifier, state, nonce };

    const params = new URLSearchParams({
      client_id:             CLIENT_ID,
      redirect_uri:          REDIRECT,
      response_type:         'code',
      scope:                 'openid email profile',
      state,
      nonce,
      code_challenge:        pkceChallenge(verifier),
      code_challenge_method: 'S256',
    });

    console.log('\n[RP] -> Redirecting to OP /authorize');
    console.log('      state    :', state);
    console.log('      verifier :', verifier.slice(0,16) + '...');

    res.writeHead(302, { Location: `${OP_BASE}/authorize?${params}` });
    return res.end();
  }

  // GET /callback -- receive code, exchange for tokens (server-to-server)
  if (url.pathname === '/callback' && req.method === 'GET') {
    const code  = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');

    if (error) {
      console.error('\n[RP] ERROR: OP returned error:', error);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Error</h2><div class="err">${esc(error)}: ${esc(url.searchParams.get('error_description')||'')}</div><br><a class="btn" href="/">Back</a></div>`));
    }

    if (!pending || state !== pending.state) {
      console.error('[RP] ERROR: State mismatch');
      res.writeHead(400, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Error</h2><div class="err">State mismatch -- possible CSRF.</div></div>`));
    }
    if (!code) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Error</h2><div class="err">Callback without code.</div></div>`));
    }

    console.log('\n[RP] <- Received callback');
    console.log('      code     :', code.slice(0,16) + '...');
    console.log('      state ok :', state);

    // Token exchange -- serwer do serwera
    console.log('[RP] -> POST /token (server-to-server)');
    const tokenRes = await fetch(`${OP_BASE}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // Confidential client: client_secret_basic. Without RP_CLIENT_SECRET the
        // OP must have this client registered as public, or /token answers 401.
        ...(CLIENT_SECRET ? { Authorization: 'Basic ' + Buffer.from(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64') } : {}),
      },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        ...(CLIENT_SECRET ? {} : { client_id: CLIENT_ID }),
        redirect_uri:  REDIRECT,
        code_verifier: pending.verifier,
      }),
    });

    const tokens = await tokenRes.json();
    const { nonce: expectedNonce } = pending;
    pending = null;

    if (!tokenRes.ok) {
      console.error('[RP] ERROR: Token error:', tokens);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Token Error</h2><pre>${esc(JSON.stringify(tokens,null,2))}</pre><br><a class="btn" href="/">Back</a></div>`));
    }

    let jwt;
    try {
      jwt = await verifyIdToken(tokens.id_token, expectedNonce);
    } catch (e) {
      console.error('[RP] ERROR: id_token rejected:', e.message);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>ID Token rejected</h2><div class="err">${esc(e.message)}</div><br><a class="btn" href="/">Back</a></div>`));
    }
    session = { ...tokens, payload: jwt.payload, header: jwt.header };

    console.log('[RP] Token exchange complete');
    console.log('      sub          :', jwt.payload.sub);
    console.log('      email        :', jwt.payload.email);
    console.log('      access_token :', tokens.access_token.slice(0,20) + '...');
    console.log('      id_token     :', tokens.id_token.slice(0,60) + '...');
    console.log('      JWT payload  :', JSON.stringify(jwt.payload, null, 2));

    res.writeHead(302, { Location: '/' });
    return res.end();
  }

  // GET /signout
  if (url.pathname === '/signout') {
    session = null;
    res.writeHead(302, { Location: '/' });
    return res.end();
  }

  res.writeHead(404);
  res.end('Not found');
}

http.createServer((req, res) => {
  // An exception in an async route used to be an unhandled rejection that
  // took the whole RP down -- answer 500 and stay up.
  router(req, res).catch(e => {
    console.error('[RP] ERROR:', e);
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/html' });
    res.end(page(`<div class="card"><h2>RP error</h2><div class="err">${esc(e.message)}</div></div>`));
  });
}).listen(RP_PORT, () => {
  console.log(`\nEncedo Test RP -- http://localhost:${RP_PORT}`);
  console.log(`   OP base     : ${OP_BASE}`);
  console.log(`   client_id   : ${CLIENT_ID}`);
  console.log(`   redirect_uri: ${REDIRECT}`);
  console.log(`\n   Open http://localhost:${RP_PORT} in browser\n`);
});
