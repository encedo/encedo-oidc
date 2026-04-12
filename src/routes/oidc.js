import { Router }                                from 'express';
import { randomBytes, createHash, createPublicKey, verify } from 'crypto';
import { fileURLToPath }                         from 'url';
import { dirname, resolve }                      from 'path';
import redis                                     from '../services/redis.js';
import { logSecurity, SEC }                      from '../services/securityLog.js';
import { rateLimit }                             from '../middleware/rateLimit.js';
import { validate, vState, vNonce, vCodeChallenge, vCodeVerifier, vSignature } from '../middleware/validate.js';

const router = Router();

// --- Paths ----------------------------------------------------
const __dirname   = dirname(fileURLToPath(import.meta.url));
const TRUSTED_APP = resolve(__dirname, '../../signin.html');

// --- Key type configuration -----------------------------------

/** JWT alg value per key type. */
const JWT_ALG = {
  Ed25519: 'EdDSA',
  P256:    'ES256',
  P384:    'ES384',
  P521:    'ES512',
};

/** Node.js hash for ECDSA verify. */
const ECDSA_HASH = { P256: 'sha256', P384: 'sha384', P521: 'sha512' };

/** JWK crv name for EC keys. */
const EC_CRV = { P256: 'P-256', P384: 'P-384', P521: 'P-521' };

// --- Helpers --------------------------------------------------

const b64url    = buf => Buffer.from(buf).toString('base64url');
const b64urlStr = str => Buffer.from(str).toString('base64url');

/**
 * Verify signature -- type-aware.
 * key_type  : 'Ed25519' | 'P256' | 'P384' | 'P521' (defaults to Ed25519)
 * pubkeyHex : hex-encoded raw public key bytes
 * message   : string that was signed
 * sigB64url : base64url signature from HSM
 */
function verifySignature(key_type, pubkeyHex, message, sigB64url) {
  const pubBytes = Buffer.from(pubkeyHex, 'hex');
  const sigBuf   = Buffer.from(sigB64url, 'base64url');
  const msgBuf   = Buffer.from(message);

  if (!key_type || key_type === 'Ed25519') {
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const pubkeyDer  = Buffer.concat([spkiPrefix, pubBytes]);
    const publicKey  = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
    return verify(null, msgBuf, publicKey, sigBuf);
  }

  // ECDSA: pubBytes = raw X||Y (no 04 prefix)
  const half = pubBytes.length / 2;
  const x    = pubBytes.subarray(0, half).toString('base64url');
  const y    = pubBytes.subarray(half).toString('base64url');
  const crv  = EC_CRV[key_type];
  const publicKey = createPublicKey({ key: { kty: 'EC', crv, x, y }, format: 'jwk' });
  return verify(ECDSA_HASH[key_type], msgBuf, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBuf);
}

/**
 * Build a JWK entry from a user record.
 * key_type defaults to 'Ed25519' for backwards compatibility with old enrollments.
 */
function buildJwk(u) {
  const kt = u.key_type || 'Ed25519';
  const pubBytes = Buffer.from(u.pubkey, 'hex');

  if (kt === 'Ed25519') {
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x:   b64url(pubBytes),
      kid: u.kid,
      alg: 'EdDSA',
      use: 'sig',
    };
  }

  // ECDSA: pubBytes = raw X||Y
  const half = pubBytes.length / 2;
  return {
    kty: 'EC',
    crv: EC_CRV[kt],
    x:   b64url(pubBytes.subarray(0, half)),
    y:   b64url(pubBytes.subarray(half)),
    kid: u.kid,
    alg: JWT_ALG[kt],
    use: 'sig',
  };
}

// --- JWKS in-memory cache (60s TTL) ---------------------------
let jwksCache = null; // { keys: [...], expiresAt: ms }
export function invalidateJwksCache() { jwksCache = null; }

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

/** Find a single user by username via O(1) index. Returns raw Redis hash or null. */
async function findUserByUsername(username) {
  const sub = await redis.hGet('username_index', username);
  if (!sub) return null;
  const u = await redis.hGetAll(`user:${sub}`);
  return u?.sub ? u : null;
}

// --- 1. GET /.well-known/openid-configuration -----------------
export function discoveryHandler(_req, res) {
  const issuer = process.env.ISSUER;
  res.json({
    issuer,
    authorization_endpoint:                `${issuer}/authorize`,
    token_endpoint:                         `${issuer}/token`,
    userinfo_endpoint:                      `${issuer}/userinfo`,
    jwks_uri:                               `${issuer}/jwks.json`,
    end_session_endpoint:                   `${issuer}/logout`,
    scopes_supported:                       ['openid', 'email', 'profile'],
    response_types_supported:               ['code'],
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported:  ['EdDSA', 'ES256', 'ES384', 'ES512'],
    userinfo_signing_alg_values_supported:  ['none'],
    token_endpoint_auth_methods_supported:  ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported:       ['S256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce',
                       'name', 'email', 'preferred_username'],
  });
}

// --- 2. GET /jwks.json ----------------------------------------
router.get('/jwks.json', async (req, res, next) => {
  try {
    if (!jwksCache || Date.now() > jwksCache.expiresAt) {
      const users = await getAllUsers();
      jwksCache = {
        keys: users
          .filter(u => u.pubkey && u.kid)
          .map(u => buildJwk(u)),
        expiresAt: Date.now() + 60_000,
      };
    }

    let keys = jwksCache.keys;
    if (req.query.kid) keys = keys.filter(k => k.kid === req.query.kid);

    // 1h cache, stale-while-revalidate for smooth key rotation
    res.setHeader('Cache-Control', 'public, max-age=3600, stale-while-revalidate=86400');
    res.json({ keys });
  } catch (err) { next(err); }
});

// --- 3. GET /authorize -- validate params, serve Trusted App ---
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

// --- 4. POST /authorize/login ---------------------------------
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

      // Find user -- prefer direct sub lookup, fallback to username scan
      let user;
      if (subParam?.trim()) {
        const raw = await redis.hGetAll(`user:${subParam.trim()}`);
        user = (raw?.sub) ? raw : null;
      } else {
        user = await findUserByUsername(username.trim());
      }

      // Unified error -- do not reveal whether user exists, is unauthorized, or incomplete
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

      const keyType = user.key_type || 'Ed25519';
      const header  = { alg: JWT_ALG[keyType] ?? 'EdDSA', kid: user.kid };
      const payload = {
        iss:                process.env.ISSUER,
        sub:                user.sub,
        aud:                client_id,
        iat:                now,
        exp:                now + idTokenTtl,
        auth_time:          now,
        jti:                randomBytes(16).toString('base64url'),
        ...(nonce ? { nonce } : {}),
        email:              user.email,
        name:               user.name,
        preferred_username: user.username,
      };

      const signing_input = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(payload))}`;

      // Create pending session -- kid anchored here, cannot be changed by frontend
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

      await logSecurity(SEC.LOGIN_OK, { sub: user.sub, username: user.username, client_id, ip: req.ip });
      console.log(`[OIDC] Login initiated: client=${client_id} session=${session_id.slice(0, 8)}...`);

      res.json({
        session_id,
        signing_input,
        user_name:     user.name,
        user_username: user.username,
        client_name:   clientRaw.name || client_id,
        key_type:      keyType,
      });

    } catch (err) { next(err); }
  }
);

// --- 5. POST /authorize/confirm -------------------------------
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
        await logSecurity(SEC.SIG_FAIL, { sub: pending.sub, username: userRaw.username, reason: 'kid_mismatch', ip: req.ip });
        return res.status(400).json({ error: 'invalid_session', error_description: 'key mismatch' });
      }

      // Verify signature -- pubkey always from Redis, never from frontend
      let valid = false;
      try {
        valid = verifySignature(userRaw.key_type, userRaw.pubkey, pending.signing_input, signature);
      } catch {
        valid = false;
      }

      if (!valid) {
        console.warn(`[OIDC] Signature verification failed for sub=${pending.sub}`);
        await logSecurity(SEC.SIG_FAIL, { sub: pending.sub, username: userRaw.username, reason: 'bad_signature', client_id: pending.client_id, ip: req.ip });
        return res.status(400).json({ error: 'invalid_signature' });
      }

      const id_token = `${pending.signing_input}.${signature}`;

      // Emit auth code -- id_token stored here, /token just retrieves it
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

      await logSecurity(SEC.SIG_OK, { sub: pending.sub, username: userRaw.username, client_id: pending.client_id, ip: req.ip });

      console.log(`[OIDC] Auth confirmed: client=${pending.client_id} session=${session_id.slice(0, 8)}...`);

      const location = new URL(pending.redirect_uri);
      location.searchParams.set('code', code);
      if (pending.state) location.searchParams.set('state', pending.state);

      res.json({ redirect_url: location.toString() });

    } catch (err) { next(err); }
  }
);

// --- 6. POST /token -------------------------------------------
router.post('/token',
  rateLimit({ prefix: 'token', max: 20, window: 60 }),
  async (req, res, next) => {
    try {
      let {
        grant_type, code, redirect_uri,
        client_id, client_secret, code_verifier,
      } = req.body;

      // M6: also accept client credentials via HTTP Basic Auth (RFC 6749 s.2.3.1)
      const basicHeader = req.headers['authorization'];
      if (basicHeader?.startsWith('Basic ')) {
        const decoded = Buffer.from(basicHeader.slice(6), 'base64').toString();
        const colon   = decoded.indexOf(':');
        if (colon > 0) {
          client_id     = decoded.slice(0, colon);
          client_secret = decoded.slice(colon + 1);
        }
      }

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

      // Track active tokens per user -- enables revocation on user delete.
      // SET TTL must never shrink: if an older token has a longer lifetime,
      // a new login with a shorter TTL must not cut off the SET before that token expires.
      const setKey = `user_tokens:${codeData.sub}`;
      await redis.sAdd(setKey, accessKey);
      const currentTtl = await redis.ttl(setKey);
      const newTtl = accessTokenTtl + 60;
      if (currentTtl < 0 || newTtl > currentTtl) {
        await redis.expire(setKey, newTtl);
      }

      const tokenUsername = await redis.hGet(`user:${codeData.sub}`, 'username');
      await logSecurity(SEC.TOKEN_ISSUED, { sub: codeData.sub, username: tokenUsername ?? undefined, client_id, ip: req.ip });

      console.log(`[OIDC] Token issued: client=${client_id} expires_in=${accessTokenTtl}s`);

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

// --- 7. GET|POST /userinfo ------------------------------------
// RFC 6750: token via Authorization header (GET/POST) or body param (POST only)
async function userinfoHandler(req, res, next) {
  try {
    const authHeader = req.headers['authorization'] ?? '';
    const token = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : req.body?.access_token ?? null;   // POST body fallback (RFC 6750 s.2.2)

    if (!token) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'invalid_token' });
    }

    const sessionRaw = await redis.get(`access:${token}`);
    if (!sessionRaw) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'token expired or not found' });
    }
    const session = JSON.parse(sessionRaw);

    const userRaw = await redis.hGetAll(`user:${session.sub}`);
    if (!userRaw?.sub) {
      return res.status(400).json({ error: 'invalid_token', error_description: 'user not found' });
    }

    const customClaims = JSON.parse(userRaw.custom_claims ?? '{}');
    const hsmUrlInUserinfo = userRaw.hsm_url_in_userinfo !== '0';

    res.json({
      sub:                userRaw.sub,
      name:               userRaw.name,
      email:              userRaw.email,
      preferred_username: userRaw.username,
      ...(hsmUrlInUserinfo && userRaw.hsm_url ? { hsm_url: userRaw.hsm_url } : {}),
      ...customClaims,
    });

  } catch (err) { next(err); }
}

router.get('/userinfo',  userinfoHandler);
router.post('/userinfo', userinfoHandler);

// --- 8. GET /logout (RP-initiated logout) ---------------------
router.get('/logout',
  rateLimit({ prefix: 'logout', max: 20, window: 60 }),
  async (req, res, next) => {
    const { id_token_hint, post_logout_redirect_uri, state } = req.query;

    function finish() {
      if (post_logout_redirect_uri) {
        try {
          const url = new URL(post_logout_redirect_uri);
          if (state) url.searchParams.set('state', state);
          return res.redirect(url.toString());
        } catch {
          return res.status(400).json({ error: 'invalid_request', error_description: 'invalid post_logout_redirect_uri' });
        }
      }
      res.json({ logged_out: true });
    }

    if (!id_token_hint) return finish();

    try {
      // Decode JWT hint (header.payload.signature)
      const parts = id_token_hint.split('.');
      if (parts.length !== 3) return finish();

      let payload;
      try {
        payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      } catch { return finish(); }

      const sub = payload?.sub;
      if (!sub) return finish();

      // Verify issuer -- reject tokens from foreign OIDC providers
      const issuerCheck = process.env.ISSUER ?? '';
      if (issuerCheck && payload.iss !== issuerCheck) {
        await logSecurity(SEC.LOGOUT, { result: 'wrong_issuer', ip: req.ip });
        return finish();
      }

      // Load user
      const userRaw = await redis.hGetAll(`user:${sub}`);
      if (!userRaw?.pubkey) {
        await logSecurity(SEC.LOGOUT, { sub, result: 'user_not_found', ip: req.ip });
        return finish();
      }

      // Verify JWT signature -- prevents one user from logging out another
      let valid = false;
      try {
        valid = verifySignature(userRaw.key_type, userRaw.pubkey, `${parts[0]}.${parts[1]}`, parts[2]);
      } catch { valid = false; }

      if (!valid) {
        await logSecurity(SEC.LOGOUT, { sub, result: 'invalid_signature', ip: req.ip });
        return finish(); // redirect anyway -- logout is fail-safe direction
      }

      // Revoke all active access tokens
      const tokenKeys = await redis.sMembers(`user_tokens:${sub}`);
      if (tokenKeys.length > 0) {
        const pipeline = redis.multi();
        for (const k of tokenKeys) pipeline.del(k);
        pipeline.del(`user_tokens:${sub}`);
        await pipeline.exec();
      }

      await logSecurity(SEC.LOGOUT, {
        sub, username: userRaw.username, result: 'ok', revokedTokens: tokenKeys.length, ip: req.ip,
      });
      console.log(`[OIDC] Logout: revoked=${tokenKeys.length} tokens`);
      finish();

    } catch (err) { next(err); }
  }
);

// --- Internal helpers -----------------------------------------

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
