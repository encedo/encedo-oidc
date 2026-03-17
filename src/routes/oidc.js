import { Router }                                from 'express';
import { randomBytes, createHash, createPublicKey, verify } from 'crypto';
import { fileURLToPath }                         from 'url';
import { dirname, resolve }                      from 'path';
import redis                                     from '../services/redis.js';
import { logSecurity, SEC }                      from '../services/securityLog.js';
import { rateLimit }                             from '../middleware/rateLimit.js';
import { validate, vState, vNonce, vCodeChallenge, vCodeVerifier, vSignature } from '../middleware/validate.js';

const router = Router();

// ─── Paths ────────────────────────────────────────────────────
const __dirname   = dirname(fileURLToPath(import.meta.url));
const TRUSTED_APP = resolve(__dirname, '../../signin.html');

// ─── Helpers ──────────────────────────────────────────────────

const b64url    = buf => Buffer.from(buf).toString('base64url');
const b64urlStr = str => Buffer.from(str).toString('base64url');

/** Verify Ed25519 signature. pubkeyHex = 32-byte raw public key (hex). */
function verifyEdDSA(pubkeyHex, signingInput, signatureB64url) {
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const pubkeyDer  = Buffer.concat([spkiPrefix, Buffer.from(pubkeyHex, 'hex')]);
  const publicKey  = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
  const sigBuf     = Buffer.from(signatureB64url, 'base64url');
  return verify(null, Buffer.from(signingInput), publicKey, sigBuf);
}

/** Fetch all users from Redis (used by /jwks.json). */
async function getAllUsers() {
  const subs = await redis.sMembers('users');
  if (subs.length === 0) return [];
  const pipeline = redis.multi();
  for (const sub of subs) pipeline.hGetAll(`user:${sub}`);
  const results = await pipeline.exec();
  return results
    .filter(r => r && Object.keys(r).length > 0)
    .map(r => ({ ...r, clients: JSON.parse(r.clients ?? '[]') }));
}

/** Find a single user by username. Returns raw Redis hash or null. */
async function findUserByUsername(username) {
  const subs = await redis.sMembers('users');
  for (const sub of subs) {
    const u = await redis.hGetAll(`user:${sub}`);
    if (u?.username === username) return u;
  }
  return null;
}

// ─── 1. GET /.well-known/openid-configuration ─────────────────
export function discoveryHandler(_req, res) {
  const issuer = process.env.ISSUER;
  res.json({
    issuer,
    authorization_endpoint:                `${issuer}/authorize`,
    token_endpoint:                         `${issuer}/token`,
    userinfo_endpoint:                      `${issuer}/userinfo`,
    jwks_uri:                               `${issuer}/jwks.json`,
    scopes_supported:                       ['openid', 'email', 'profile'],
    response_types_supported:               ['code'],
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported:  ['EdDSA'],
    userinfo_signing_alg_values_supported:  ['none'],
    token_endpoint_auth_methods_supported:  ['client_secret_post', 'none'],
    code_challenge_methods_supported:       ['S256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce',
                       'name', 'email', 'preferred_username'],
  });
}

// ─── 2. GET /jwks.json ────────────────────────────────────────
router.get('/jwks.json', async (req, res, next) => {
  try {
    const users = await getAllUsers();
    let keys = users
      .filter(u => u.pubkey && u.kid)
      .map(u => ({
        kty: 'OKP',
        crv: 'Ed25519',
        x:   b64url(Buffer.from(u.pubkey, 'hex')),
        kid: u.kid,
        alg: 'EdDSA',
        use: 'sig',
      }));

    if (req.query.kid) keys = keys.filter(k => k.kid === req.query.kid);

    // 1h cache, stale-while-revalidate for smooth key rotation
    res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=86400');
    res.json({ keys });
  } catch (err) { next(err); }
});

// ─── 3. GET /authorize — validate params, serve Trusted App ───
router.get('/authorize', async (req, res, next) => {
  try {
    const {
      client_id, redirect_uri, response_type, scope,
      state, nonce, code_challenge, code_challenge_method,
    } = req.query;

    if (response_type !== 'code') {
      return sendAuthError(res, redirect_uri, 'unsupported_response_type', state);
    }

    const clientRaw = await redis.hGetAll(`client:${client_id}`);
    if (!clientRaw?.client_id) {
      return sendAuthError(res, redirect_uri, 'unauthorized_client', state);
    }

    const allowedRedirects = JSON.parse(clientRaw.redirect_uris ?? '[]');
    if (!allowedRedirects.includes(redirect_uri)) {
      return res.status(400).json({ error: 'invalid_redirect_uri' });
    }

    const requestedScopes = (scope ?? '').split(' ').filter(Boolean);
    if (!requestedScopes.includes('openid')) {
      return sendAuthError(res, redirect_uri, 'invalid_scope', state);
    }
    const allowedScopes = JSON.parse(clientRaw.scopes ?? '["openid"]');
    if (!requestedScopes.every(s => allowedScopes.includes(s))) {
      return sendAuthError(res, redirect_uri, 'invalid_scope', state);
    }

    if (clientRaw.pkce === 'true') {
      if (!code_challenge || code_challenge_method !== 'S256') {
        return sendAuthError(res, redirect_uri, 'invalid_request', state,
          'PKCE S256 required for this client');
      }
    }

    const paramErr = validate(
      vNonce(nonce),
      vState(state),
      code_challenge ? vCodeChallenge(code_challenge) : null,
    );
    if (paramErr) return sendAuthError(res, redirect_uri, 'invalid_request', state, paramErr);

    res.sendFile(TRUSTED_APP);

  } catch (err) { next(err); }
});

// ─── 4. POST /authorize/login ─────────────────────────────────
router.post('/authorize/login',
  rateLimit({ prefix: 'login', max: 20, window: 60,
    keyFn: req => req.body?.client_id ?? req.ip }),
  async (req, res, next) => {
    try {
      const {
        sub: subParam, username, client_id, redirect_uri, scope,
        state, nonce, code_challenge, code_challenge_method, response_type,
      } = req.body;

      if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type' });
      }

      const clientRaw = await redis.hGetAll(`client:${client_id}`);
      if (!clientRaw?.client_id) {
        return res.status(400).json({ error: 'unauthorized_client' });
      }

      const allowedRedirects = JSON.parse(clientRaw.redirect_uris ?? '[]');
      if (!allowedRedirects.includes(redirect_uri)) {
        return res.status(400).json({ error: 'invalid_redirect_uri' });
      }

      const requestedScopes = (scope ?? '').split(' ').filter(Boolean);
      if (!requestedScopes.includes('openid')) {
        return res.status(400).json({ error: 'invalid_scope' });
      }
      const allowedScopes = JSON.parse(clientRaw.scopes ?? '["openid"]');
      if (!requestedScopes.every(s => allowedScopes.includes(s))) {
        return res.status(400).json({ error: 'invalid_scope' });
      }

      if (clientRaw.pkce === 'true') {
        if (!code_challenge || code_challenge_method !== 'S256') {
          return res.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 required' });
        }
      }

      const paramErr = validate(
        vNonce(nonce),
        vState(state),
        code_challenge ? vCodeChallenge(code_challenge) : null,
      );
      if (paramErr) return res.status(400).json({ error: 'invalid_request', error_description: paramErr });

      if (!subParam?.trim() && !username?.trim()) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'missing sub or username' });
      }

      // Find user — prefer direct sub lookup, fallback to username scan
      let user;
      if (subParam?.trim()) {
        const raw = await redis.hGetAll(`user:${subParam.trim()}`);
        user = (raw?.sub) ? raw : null;
      } else {
        user = await findUserByUsername(username.trim());
      }

      // Unified error — do not reveal whether user exists, is unauthorized, or incomplete
      if (!user || !JSON.parse(user.clients ?? '[]').includes(client_id) || !user.pubkey || !user.kid) {
        await logSecurity(SEC.LOGIN_FAIL, {
          client_id,
          hint: !user ? 'user_not_found' : !JSON.parse(user.clients ?? '[]').includes(client_id) ? 'client_not_authorized' : 'enrollment_incomplete',
          ip: req.ip,
        });
        return res.status(400).json({ error: 'access_denied', error_description: 'invalid credentials' });
      }

      // Build signing_input = base64url(header).base64url(payload)
      const now        = Math.floor(Date.now() / 1000);
      const idTokenTtl = parseInt(clientRaw.id_token_ttl, 10) || 3600;

      const header  = { alg: 'EdDSA', kid: user.kid };
      const payload = {
        iss:                process.env.ISSUER,
        sub:                user.sub,
        aud:                client_id,
        iat:                now,
        exp:                now + idTokenTtl,
        jti:                randomBytes(16).toString('base64url'),
        ...(nonce ? { nonce } : {}),
        email:              user.email,
        name:               user.name,
        preferred_username: user.username,
      };

      const signing_input = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(payload))}`;

      // Create pending session — kid anchored here, cannot be changed by frontend
      const session_id = randomBytes(32).toString('base64url');
      await redis.set(`pending:${session_id}`, JSON.stringify({
        sub:            user.sub,
        kid:            user.kid,
        client_id,
        scope:          requestedScopes.join(' '),
        nonce:          nonce ?? null,
        code_challenge: code_challenge ?? null,
        redirect_uri,
        state:          state ?? null,
        signing_input,
      }), { EX: 120 });

      await logSecurity(SEC.LOGIN_OK, { sub: user.sub, client_id, ip: req.ip });
      console.log(`[OIDC] Login initiated: user=${user.username} client=${client_id} session=${session_id.slice(0, 8)}…`);

      res.json({
        session_id,
        signing_input,
        user_name:     user.name,
        user_username: user.username,
      });

    } catch (err) { next(err); }
  }
);

// ─── 5. POST /authorize/confirm ───────────────────────────────
router.post('/authorize/confirm',
  rateLimit({ prefix: 'confirm', max: 10, window: 60 }),
  async (req, res, next) => {
    try {
      const { session_id, signature } = req.body;

      if (!session_id || !signature) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'missing session_id or signature' });
      }

      const sigErr = vSignature(signature);
      if (sigErr) return res.status(400).json({ error: 'invalid_request', error_description: sigErr });

      // Load & consume pending session (one-time use)
      const pendingRaw = await redis.getDel(`pending:${session_id}`);
      if (!pendingRaw) {
        return res.status(400).json({ error: 'invalid_session', error_description: 'session expired or not found' });
      }
      const pending = JSON.parse(pendingRaw);

      // Load user
      const userRaw = await redis.hGetAll(`user:${pending.sub}`);
      if (!userRaw?.sub) {
        return res.status(400).json({ error: 'invalid_session', error_description: 'user not found' });
      }

      // Verify kid: session kid must match user's current kid
      if (userRaw.kid !== pending.kid) {
        console.warn(`[OIDC] kid mismatch for sub=${pending.sub}`);
        await logSecurity(SEC.SIG_FAIL, { sub: pending.sub, reason: 'kid_mismatch', ip: req.ip });
        return res.status(400).json({ error: 'invalid_session', error_description: 'key mismatch' });
      }

      // Verify Ed25519 signature — pubkey always from Redis, never from frontend
      let valid = false;
      try {
        valid = verifyEdDSA(userRaw.pubkey, pending.signing_input, signature);
      } catch {
        valid = false;
      }

      if (!valid) {
        console.warn(`[OIDC] Signature verification failed for sub=${pending.sub}`);
        await logSecurity(SEC.SIG_FAIL, { sub: pending.sub, reason: 'bad_signature', client_id: pending.client_id, ip: req.ip });
        return res.status(400).json({ error: 'invalid_signature' });
      }

      // Assemble final signed JWT
      const id_token = `${pending.signing_input}.${signature}`;

      // Emit auth code — id_token stored here, /token just retrieves it
      const code = randomBytes(32).toString('base64url');
      await redis.set(`code:${code}`, JSON.stringify({
        sub:            pending.sub,
        client_id:      pending.client_id,
        scope:          pending.scope,
        nonce:          pending.nonce,
        code_challenge: pending.code_challenge,
        redirect_uri:   pending.redirect_uri,
        id_token,
      }), { EX: 60 });

      await logSecurity(SEC.SIG_OK, { sub: pending.sub, client_id: pending.client_id });

      // Decode JWT payload for logging
      const [jwtHeader, jwtPayload] = pending.signing_input.split('.');
      const decodedHeader  = JSON.parse(Buffer.from(jwtHeader,  'base64url').toString());
      const decodedPayload = JSON.parse(Buffer.from(jwtPayload, 'base64url').toString());

      console.log('\n[OIDC] ─── Auth Confirmed ───────────────────────');
      console.log('  sub      :', pending.sub);
      console.log('  client   :', pending.client_id);
      console.log('  scope    :', pending.scope);
      console.log('  code     :', code);
      console.log('  JWT header  :', JSON.stringify(decodedHeader));
      console.log('  JWT payload :', JSON.stringify(decodedPayload, null, 2).replace(/^/gm, '    ').trim());
      console.log('  id_token :', id_token.slice(0, 60) + '…');
      console.log('─────────────────────────────────────────────────\n');

      const location = new URL(pending.redirect_uri);
      location.searchParams.set('code', code);
      if (pending.state) location.searchParams.set('state', pending.state);

      res.json({ redirect_url: location.toString() });

    } catch (err) { next(err); }
  }
);

// ─── 6. POST /token ───────────────────────────────────────────
router.post('/token',
  rateLimit({ prefix: 'token', max: 20, window: 60 }),
  async (req, res, next) => {
    try {
      const {
        grant_type, code, redirect_uri,
        client_id, client_secret, code_verifier,
      } = req.body;

      if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
      }
      if (!code) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'missing code' });
      }

      // Consume auth code (one-time use)
      const codeDataRaw = await redis.getDel(`code:${code}`);
      if (!codeDataRaw) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'code expired or already used' });
      }
      const codeData = JSON.parse(codeDataRaw);

      if (codeData.client_id !== client_id) {
        return res.status(400).json({ error: 'invalid_grant' });
      }
      if (codeData.redirect_uri !== redirect_uri) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      }

      const clientRaw = await redis.hGetAll(`client:${client_id}`);
      if (!clientRaw?.client_id) {
        return res.status(401).json({ error: 'invalid_client' });
      }

      // Authenticate client: PKCE or client_secret (timing-safe)
      if (codeData.code_challenge) {
        if (!code_verifier) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier required' });
        }
        const verifierErr = vCodeVerifier(code_verifier);
        if (verifierErr) return res.status(400).json({ error: 'invalid_request', error_description: verifierErr });
        const expected = createHash('sha256').update(code_verifier).digest('base64url');
        // timing-safe compare
        let match = false;
        try {
          match = timingSafeEqual(Buffer.from(expected), Buffer.from(codeData.code_challenge));
        } catch { match = false; }
        if (!match) {
          return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier mismatch' });
        }
      } else {
        if (!client_secret) {
          return res.status(401).json({ error: 'invalid_client' });
        }
        let match = false;
        try {
          const a = Buffer.from(client_secret);
          const b = Buffer.from(clientRaw.client_secret ?? '');
          match = a.length === b.length && timingSafeEqual(a, b);
        } catch { match = false; }
        if (!match) {
          return res.status(401).json({ error: 'invalid_client' });
        }
      }

      const { id_token } = codeData;

      const accessTokenTtl = parseInt(clientRaw.access_token_ttl, 10) || 3600;
      const accessToken    = randomBytes(32).toString('base64url');
      const accessKey      = `access:${accessToken}`;
      await redis.set(accessKey, JSON.stringify({
        sub:       codeData.sub,
        client_id,
        scope:     codeData.scope,
      }), { EX: accessTokenTtl });

      // Track active tokens per user — enables revocation on user delete
      await redis.sAdd(`user_tokens:${codeData.sub}`, accessKey);
      await redis.expire(`user_tokens:${codeData.sub}`, accessTokenTtl + 60);

      await logSecurity(SEC.TOKEN_ISSUED, { sub: codeData.sub, client_id, ip: req.ip });

      console.log('\n[OIDC] ─── Token Issued ─────────────────────────');
      console.log('  sub          :', codeData.sub);
      console.log('  client       :', client_id);
      console.log('  access_token :', accessToken.slice(0, 16) + '…');
      console.log('  id_token     :', id_token.slice(0, 60) + '…');
      console.log('  expires_in   :', accessTokenTtl + 's');
      console.log('─────────────────────────────────────────────────\n');

      res.json({
        access_token: accessToken,
        id_token,
        token_type:   'Bearer',
        expires_in:   accessTokenTtl,
        scope:        codeData.scope,
      });

    } catch (err) { next(err); }
  }
);

// ─── 7. GET /userinfo ─────────────────────────────────────────
router.get('/userinfo', async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    const token = authHeader.slice(7);

    const sessionRaw = await redis.get(`access:${token}`);
    if (!sessionRaw) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'token expired or not found' });
    }
    const session = JSON.parse(sessionRaw);

    const userRaw = await redis.hGetAll(`user:${session.sub}`);
    if (!userRaw?.sub) {
      return res.status(400).json({ error: 'invalid_token', error_description: 'user not found' });
    }

    res.json({
      sub:                userRaw.sub,
      name:               userRaw.name,
      email:              userRaw.email,
      preferred_username: userRaw.username,
    });

  } catch (err) { next(err); }
});

// ─── Internal helpers ─────────────────────────────────────────

import { timingSafeEqual } from 'crypto';

function sendAuthError(res, redirect_uri, error, state, description) {
  try {
    const location = new URL(redirect_uri);
    location.searchParams.set('error', error);
    if (description) location.searchParams.set('error_description', description);
    if (state)       location.searchParams.set('state', state);
    return res.redirect(location.toString());
  } catch {
    return res.status(400).json({ error, ...(description ? { error_description: description } : {}) });
  }
}

export default router;
