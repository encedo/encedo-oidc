import 'dotenv/config';
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

import { requireAdminAuth, requireAdminNetwork } from './middleware/auth.js';
import { errorHandler }                          from './middleware/errorHandler.js';
import { rateLimit }                             from './middleware/rateLimit.js';
import adminUsers                                from './routes/adminUsers.js';
import adminClients                              from './routes/adminClients.js';
import oidc, { discoveryHandler }               from './routes/oidc.js';
import enrollment                               from './routes/enrollment.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT      = resolve(__dirname, '..');

const app = express();

// ─── Trust proxy (set to 1 if behind nginx/caddy, adjust as needed) ──────────
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY);

// ─── Content-Security-Policy ──────────────────────────────────────────────────
// connect-src: 'self' (OIDC backend) + *.ence.do (PPA HSMs) + api.encedo.com (broker).
// EPA devices with custom domains: add via CSP_CONNECT_EXTRA env var (space-separated).
// script-src 'unsafe-inline': signin.html and enrollment.html use inline <script type="module">.
//   TODO: move inline scripts to external .js files and remove 'unsafe-inline'.
// style-src: Google Fonts CSS loaded via @import inside inline <style>.
// IPv6 not supported for HSM connections (see security.md M3).
const connectExtra = process.env.CSP_CONNECT_EXTRA ? ` ${process.env.CSP_CONNECT_EXTRA}` : '';
const CSP = [
  "default-src 'self'",
  `connect-src 'self' https://*.ence.do https://api.encedo.com${connectExtra}`,
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ');

// ─── Security headers ─────────────────────────────────────────────────────────
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

// ─── CORS — only OIDC protocol endpoints that RPs call cross-origin ───────────
// /authorize and /enrollment are served same-origin (browser UI) — no CORS needed.
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

// ─── Body parsing — size-limited ──────────────────────────────────────────────
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// ─── Static UI pages ──────────────────────────────────────────────────────────
app.get('/admin',      (_req, res) => res.sendFile(resolve(ROOT, 'admin-panel.html')));
app.get('/enrollment', (_req, res) => res.sendFile(resolve(ROOT, 'enrollment.html')));
app.get('/hem-sdk.js', (_req, res) => res.sendFile(resolve(ROOT, 'hem-sdk.js')));

// ─── /.well-known — registered directly to bypass path-to-regexp dot bug ──────
app.get('/.well-known/openid-configuration', discoveryHandler);

// ─── OIDC endpoints (public) — rate limited ────────────────────────────────────
app.use('/', oidc);

// ─── Enrollment (token-authenticated) ─────────────────────────────────────────
app.use('/enrollment', enrollment);

// ─── Admin API — network check + auth ─────────────────────────────────────────
app.use('/admin',
  requireAdminNetwork,
  requireAdminAuth,
  rateLimit({ prefix: 'admin', max: 60, window: 60 }),
);
app.use('/admin/users',   adminUsers);
app.use('/admin/clients', adminClients);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

// ─── Error handler ────────────────────────────────────────────────────────────
app.use(errorHandler);

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(`🔐 Encedo OIDC Provider — http://localhost:${PORT}`);
  console.log(`   ENV: ${process.env.NODE_ENV ?? 'development'}`);
  console.log(`   Issuer: ${process.env.ISSUER ?? '⚠ ISSUER not set'}`);
  console.log(`   Admin panel : http://localhost:${PORT}/admin`);
  if (!process.env.ADMIN_SECRET || process.env.ADMIN_SECRET === 'dev-secret-change-me') {
    console.warn('   ⚠ WARNING: ADMIN_SECRET is not set or uses default value!');
  }
});
