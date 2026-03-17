// ─────────────────────────────────────────────────────────────
//  Encedo Test RP — server-side OIDC flow
//  Port: 9876  |  Redirect: http://localhost:9876/callback
//  Usage: node rp-server.mjs
// ─────────────────────────────────────────────────────────────
import http          from 'http';
import crypto        from 'crypto';
import { URLSearchParams } from 'url';

const OP_BASE    = process.env.OP_BASE    || 'http://localhost:3000';
const CLIENT_ID  = process.env.RP_CLIENT_ID  || '';
const RP_PORT    = process.env.RP_PORT    || 9876;
const REDIRECT   = `http://localhost:${RP_PORT}/callback`;

if (!CLIENT_ID) { console.error('❌  RP_CLIENT_ID not set'); process.exit(1); }

// ── In-memory session (one user at a time — dev only) ─────────
let pending = null;   // { verifier, state, nonce }
let session = null;   // { access_token, id_token, payload }

// ── PKCE ──────────────────────────────────────────────────────
function randomB64url(n) {
  return crypto.randomBytes(n).toString('base64url');
}
function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ── JWT decode (display only — signature NOT verified here) ───
function decodeJwt(token) {
  const [h, p] = token.split('.');
  const dec = s => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
  return { header: dec(h), payload: dec(p) };
}

// ── Tiny HTML helper ─────────────────────────────────────────
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

// ── Routes ───────────────────────────────────────────────────
async function router(req, res) {
  const url = new URL(req.url, `http://localhost:${RP_PORT}`);

  // GET / — home
  if (url.pathname === '/' && req.method === 'GET') {
    if (session) {
      const p = session.payload;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`
        <div class="card">
          <h2>✓ Logged in</h2>
          <div class="row"><span class="k">name</span>  <span class="v">${p.name||'—'}</span></div>
          <div class="row"><span class="k">email</span> <span class="v">${p.email||'—'}</span></div>
          <div class="row"><span class="k">sub</span>   <span class="v">${p.sub||'—'}</span></div>
          <div class="row"><span class="k">access_token</span><span class="v green">${session.access_token.slice(0,20)}…</span></div>
          <div class="label">id_token payload</div>
          <pre>${JSON.stringify(p, null, 2)}</pre>
          <div class="label">id_token header</div>
          <pre>${JSON.stringify(session.header, null, 2)}</pre>
          <br><a class="btn" href="/signout">Sign out</a>
        </div>`));
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(page(`
      <div class="card">
        <h2>Encedo Test RP</h2>
        <div class="row"><span class="k">OP</span>         <span class="v">${OP_BASE}</span></div>
        <div class="row"><span class="k">client_id</span>  <span class="v">${CLIENT_ID}</span></div>
        <div class="row"><span class="k">redirect_uri</span><span class="v">${REDIRECT}</span></div>
        <div class="row"><span class="k">pkce</span>       <span class="v green">S256 ✓</span></div>
        <br><a class="btn" href="/signin">Sign in with Encedo</a>
      </div>`));
  }

  // GET /signin — generuj PKCE, redirect do OP
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

    console.log('\n[RP] → Redirecting to OP /authorize');
    console.log('      state    :', state);
    console.log('      verifier :', verifier.slice(0,16) + '…');

    res.writeHead(302, { Location: `${OP_BASE}/authorize?${params}` });
    return res.end();
  }

  // GET /callback — odbierz code, wymień na tokeny (serwer↔serwer)
  if (url.pathname === '/callback' && req.method === 'GET') {
    const code  = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');

    if (error) {
      console.error('\n[RP] ✗ OP returned error:', error);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Error</h2><div class="err">${error}: ${url.searchParams.get('error_description')||''}</div><br><a class="btn" href="/">Back</a></div>`));
    }

    if (!pending || state !== pending.state) {
      console.error('[RP] ✗ State mismatch');
      res.writeHead(400, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Error</h2><div class="err">State mismatch — possible CSRF.</div></div>`));
    }

    console.log('\n[RP] ← Received callback');
    console.log('      code     :', code.slice(0,16) + '…');
    console.log('      state ✓  :', state);

    // Token exchange — serwer do serwera
    console.log('[RP] → POST /token (server-to-server)');
    const tokenRes = await fetch(`${OP_BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        client_id:     CLIENT_ID,
        redirect_uri:  REDIRECT,
        code_verifier: pending.verifier,
      }),
    });

    const tokens = await tokenRes.json();
    pending = null;

    if (!tokenRes.ok) {
      console.error('[RP] ✗ Token error:', tokens);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(page(`<div class="card"><h2>Token Error</h2><pre>${JSON.stringify(tokens,null,2)}</pre><br><a class="btn" href="/">Back</a></div>`));
    }

    const jwt = decodeJwt(tokens.id_token);
    session   = { ...tokens, payload: jwt.payload, header: jwt.header };

    console.log('[RP] ✓ Token exchange complete');
    console.log('      sub          :', jwt.payload.sub);
    console.log('      email        :', jwt.payload.email);
    console.log('      access_token :', tokens.access_token.slice(0,20) + '…');
    console.log('      id_token     :', tokens.id_token.slice(0,60) + '…');
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

http.createServer(router).listen(RP_PORT, () => {
  console.log(`\n🌐 Encedo Test RP — http://localhost:${RP_PORT}`);
  console.log(`   OP base     : ${OP_BASE}`);
  console.log(`   client_id   : ${CLIENT_ID}`);
  console.log(`   redirect_uri: ${REDIRECT}`);
  console.log(`\n   Open http://localhost:${RP_PORT} in browser\n`);
});
