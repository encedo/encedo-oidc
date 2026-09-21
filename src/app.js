import 'dotenv/config';
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';

const GIT_COMMIT = (() => {
  try { return execSync('git rev-parse --short HEAD', { stdio: ['ignore','pipe','ignore'] }).toString().trim(); }
  catch { return process.env.GIT_COMMIT || 'unknown'; }
})();
// Release version: package.json is bumped with every tag (README, Releasing).
const APP_VERSION = (() => {
  try { return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version; }
  catch { return 'unknown'; }
})();

import { requireAdminAuth, requireAdminNetwork } from './middleware/auth.js';
import { errorHandler }                          from './middleware/errorHandler.js';
import { rateLimit }                             from './middleware/rateLimit.js';
import adminUsers, { getAuditLog }              from './routes/adminUsers.js';
import adminClients                              from './routes/adminClients.js';
import oidc, { discoveryHandler }               from './routes/oidc.js';
import enrollment                               from './routes/enrollment.js';
import { adminInviteHandler, adminListInvitesHandler, adminDeleteInviteHandler, signupPrefillHandler, signupRegisterHandler, adminSendInviteEmailHandler } from './routes/invite.js';
import { isMailEnabled } from './services/mailer.js';
import redis, { redisAlive } from './services/redis.js';
import { confirmEmailHandler } from './routes/emailVerify.js';
import { adminInviteClientHandler, adminDeleteClientInviteHandler, signupClientPrefillHandler, signupClientRegisterHandler } from './routes/inviteClient.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT      = resolve(__dirname, '..');

const app = express();

// --- Trust proxy (set to 1 if behind nginx/caddy, adjust as needed) ----------
if (process.env.TRUST_PROXY) {
  const v = process.env.TRUST_PROXY;
  app.set('trust proxy', /^\d+$/.test(v) ? Number(v) : v);
} else {
  // Without it, req.ip behind a reverse proxy is the proxy's own address: every
  // per-IP rate limit collapses into one bucket shared by the whole internet
  // and ADMIN_ALLOWED_IPS compares against the proxy. Say so, once, the moment
  // a forwarded request shows up -- that is the configuration mistake, not the
  // absence of the variable in a bare local run.
  let warned = false;
  app.use((req, _res, next) => {
    if (!warned && req.headers['x-forwarded-for']) {
      warned = true;
      console.warn('[!] X-Forwarded-For received but TRUST_PROXY is not set -- rate limits and ADMIN_ALLOWED_IPS are keyed by the proxy address. Set TRUST_PROXY=1.');
    }
    next();
  });
}

// --- Content-Security-Policy --------------------------------------------------
// connect-src: 'self' (OIDC backend) + *.ence.do (PPA HSMs) + api.encedo.com (broker).
// EPA devices with custom domains: add via CSP_CONNECT_EXTRA env var (space-separated).
// script-src: 'self' only -- JS lives in external files and there are NO inline
//   on*= handlers either (no script-src-attr): pages dispatch clicks through
//   data-action attributes, so injected markup can never become code.
// style-src: inline <style> blocks allowed via SHA-256 hashes (no 'unsafe-inline').
//   Hashes cover exact byte content -- update if CSS changes (browser console will show new hash).
// IPv6 not supported for HSM connections (see security.md M3).
const connectExtra = process.env.CSP_CONNECT_EXTRA ? ` ${process.env.CSP_CONNECT_EXTRA}` : '';
const STYLE_HASHES = [
  "'sha256-9uNX+72e1UgDS/7qEfgEY0sg188gJIZDByvsHCm319I='", // signin.html
  "'sha256-WPNRCWjevpCuzbaeXeJXbBvLGm9JxCIVJqLNS7qCHnk='", // enrollment.html
  "'sha256-EA0irg8jKANLVH35Bh+2RzqKe3W+GIZXlbxrH4lShmg='", // admin-panel.html
  "'sha256-H7RTronIQdIsg1/OPK/veLJvD4xeJ3OUhtOwDU2wBNc='", // index.html
  "'sha256-nSvCekeiay54/8qHI5QRjPkvxVPtshpDpZx8+YGvFEc='", // landing.html
  "'sha256-aeiTjKwpQyLweFX9vVB9iij4EBs40oHYv9vg69BhU7w='", // signup.html
  "'sha256-qXZuPZxV+KsTgO6hwVLJlO7Yhnbtl+1AlknyPXSu5hI='", // signup-client.html
  "'sha256-QeAjkqncaNqHQ0XCC7p7SXeTpzgU0LJQXom27mfg4A4='", // verify-email.html
  "'sha256-aO/5eCFVjZmaJTh8HHmJld86rx45wTTYYOkF685TFCk='", // logout.html
].join(' ');
const CSP = [
  "default-src 'self'",
  `connect-src 'self' https://*.ence.do https://api.encedo.com${connectExtra}`,
  "script-src 'self'",
  `style-src 'self' ${STYLE_HASHES} https://fonts.googleapis.com`,
  "style-src-attr 'unsafe-inline'",    // inline style= attributes on elements
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

// --- Security headers ---------------------------------------------------------
app.use((_req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',             'DENY');
  res.setHeader('Referrer-Policy',             'no-referrer');
  res.setHeader('Content-Security-Policy',     CSP);
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }
  next();
});

// --- CORS -- only OIDC protocol endpoints that RPs call cross-origin -----------
// /authorize and /enrollment are served same-origin (browser UI) -- no CORS needed.
// /token and /userinfo are backend-to-backend but some SPA RPs call them from browser.
// /jwks.json and /.well-known must be universally accessible.
const CORS_PUBLIC_RE = /^\/(jwks\.json|token|userinfo|\.well-known\/)/;

app.use((req, res, next) => {
  if (!CORS_PUBLIC_RE.test(req.path)) return next();

  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- Body parsing -- size-limited ----------------------------------------------
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// --- Health check -------------------------------------------------------------
// 200 only when Redis answers: the process serves nothing useful without it,
// and the Docker HEALTHCHECK / the operator watching /status must not be told
// "ok" by an app whose only datastore is gone.
app.get('/health', async (_req, res) => {
  const redisUp = await redisAlive();
  res.status(redisUp ? 200 : 503).json({
    status: redisUp ? 'ok' : 'degraded',
    redis: redisUp ? 'up' : 'down',
    ts: new Date().toISOString(), version: APP_VERSION, commit: GIT_COMMIT, issuer: process.env.ISSUER ?? null, mail_enabled: isMailEnabled(),
  });
});

// --- Static UI pages ----------------------------------------------------------
// LANDING_PAGE=1 puts the product landing page on '/' -- meant for the public
// instance only. Every instance keeps the operator status page, at /status, and
// test/demo tenants leave it on '/' by not setting the variable.
const LANDING_PAGE = process.env.LANDING_PAGE === '1';
app.get('/',                (_req, res) => res.sendFile(resolve(ROOT, LANDING_PAGE ? 'landing.html' : 'index.html')));
app.get('/status',          (_req, res) => res.sendFile(resolve(ROOT, 'index.html')));
app.get('/landing.js',      (_req, res) => res.sendFile(resolve(ROOT, 'landing.js')));
app.get('/admin',           (_req, res) => res.sendFile(resolve(ROOT, 'admin-panel.html')));
app.get('/enrollment',      (_req, res) => res.sendFile(resolve(ROOT, 'enrollment.html')));
app.get('/signup.js',            (_req, res) => res.sendFile(resolve(ROOT, 'signup.js')));
app.get('/signup-client.js',     (_req, res) => res.sendFile(resolve(ROOT, 'signup-client.js')));
app.get('/logo.png',        (_req, res) => res.sendFile(resolve(ROOT, 'logo.png')));
app.get('/favicon.ico',    (_req, res) => res.sendFile(resolve(ROOT, 'favicon.ico')));
app.get('/index.js',        (_req, res) => res.sendFile(resolve(ROOT, 'index.js')));
// HEM SDK comes from the hem-sdk-js git submodule (pre-built browser bundle).
// The URL stays /hem-sdk.js so the UI modules keep their import path.
app.get('/hem-sdk.js',      (_req, res) => res.sendFile(resolve(ROOT, 'hem-sdk-js/hem-sdk.browser.js')));
app.get('/hem-sdk.browser.js.map', (_req, res) => res.sendFile(resolve(ROOT, 'hem-sdk-js/hem-sdk.browser.js.map')));
app.get('/hsm-common.js',   (_req, res) => res.sendFile(resolve(ROOT, 'hsm-common.js')));   // shared by signin/enrollment/signup
app.get('/logout.js',       (_req, res) => res.sendFile(resolve(ROOT, 'logout.js')));       // clears the SSO session on the /logout page
app.get('/signin.js',       (_req, res) => res.sendFile(resolve(ROOT, 'signin.js')));
app.get('/enrollment.js',   (_req, res) => res.sendFile(resolve(ROOT, 'enrollment.js')));
app.get('/admin-panel.js',  (_req, res) => res.sendFile(resolve(ROOT, 'admin-panel.js')));

// --- /.well-known -- registered directly to bypass path-to-regexp dot bug ------
app.get('/.well-known/openid-configuration', discoveryHandler);

// --- OIDC endpoints (public) -- rate limited ------------------------------------
app.use('/', oidc);

// --- Enrollment (token-authenticated) -----------------------------------------
app.use('/enrollment', enrollment);

// --- Signup (invite flow, public) ---------------------------------------------
app.get('/signup',                 (_req, res) => res.sendFile(resolve(ROOT, 'signup.html')));
app.post('/signup/prefill',        signupPrefillHandler);   // token in the body, not the query string
app.post('/signup/register',       signupRegisterHandler);

// --- Signup client (client invite flow, public) --------------------------------
app.get('/signup-client',          (_req, res) => res.sendFile(resolve(ROOT, 'signup-client.html')));
app.post('/signup-client/prefill', signupClientPrefillHandler);
app.post('/signup-client/register', signupClientRegisterHandler);

// --- Email verification (public -- the token in the link is the credential) ----
app.get('/verify-email',           (_req, res) => res.sendFile(resolve(ROOT, 'verify-email.html')));
app.get('/verify-email.js',        (_req, res) => res.sendFile(resolve(ROOT, 'verify-email.js')));
app.post('/verify-email/confirm',  rateLimit({ prefix: 'verify-email', max: 20, window: 60 }), confirmEmailHandler);

// --- Admin API -- network check + auth -----------------------------------------
// requireAdminAuth carries its own failed-attempt limiter (10 failures / min
// per IP); the general limiter behind it only ever sees authenticated calls.
app.use('/admin',
  requireAdminNetwork,
  requireAdminAuth,
  rateLimit({ prefix: 'admin', max: 60, window: 60 }),
);
app.use('/admin/users',   adminUsers);
app.use('/admin/clients', adminClients);
app.get('/admin/audit-log', getAuditLog);
app.post('/admin/invite', adminInviteHandler);
app.post('/admin/invite-client', adminInviteClientHandler);
app.get('/admin/invites', adminListInvitesHandler);
app.post('/admin/invites/:token/send-email', adminSendInviteEmailHandler);
app.delete('/admin/invites/:token', adminDeleteInviteHandler);
app.delete('/admin/client-invites/:token', adminDeleteClientInviteHandler);

// --- 404 ----------------------------------------------------------------------
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

// --- Error handler ------------------------------------------------------------
app.use(errorHandler);

// --- Start --------------------------------------------------------------------
const PORT = process.env.PORT ?? 3000;
const server = app.listen(PORT, () => {
  console.log(`Encedo OIDC Provider -- http://localhost:${PORT}`);
  console.log(`   ENV: ${process.env.NODE_ENV ?? 'development'}`);
  console.log(`   Issuer: ${process.env.ISSUER ?? '[WARNING] ISSUER not set'}`);
  console.log(`   Admin panel : http://localhost:${PORT}/admin`);
  if (!process.env.ADMIN_SECRET || process.env.ADMIN_SECRET === 'dev-secret-change-me') {
    console.warn('   [!] WARNING: ADMIN_SECRET is not set or uses default value!');
  }
  if (!process.env.ADMIN_ALLOWED_IPS) {
    console.warn('   [!] ADMIN_ALLOWED_IPS not set -- admin endpoints restricted to localhost only');
  }
});

// --- Graceful shutdown ----------------------------------------------------------
// docker stop / systemd send SIGTERM. Without a handler Node dies mid-request,
// and a multi-step Redis write (user hash, index, set) can be left half done.
// Stop accepting, let in-flight requests finish, close Redis, then exit -- with
// a hard deadline well inside Docker's 10 s grace period.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.once(sig, () => {
    console.log(`[App] ${sig} received -- shutting down`);
    const deadline = setTimeout(() => process.exit(1), 5_000);
    deadline.unref();
    server.close(async () => {
      try { await redis.quit(); } catch { /* already gone */ }
      process.exit(0);
    });
  });
}
