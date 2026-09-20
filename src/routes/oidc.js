import { Router }                                from 'express';
import { randomBytes, createHash } from 'crypto';
import { fileURLToPath }                         from 'url';
import { dirname, resolve }                      from 'path';
import redis                                     from '../services/redis.js';
import { logSecurity, SEC }                      from '../services/securityLog.js';
import { rateLimit }                             from '../middleware/rateLimit.js';
import { validate, vState, vNonce, vCodeChallenge, vCodeVerifier, vSignature } from '../middleware/validate.js';
import { revokeUserTokens } from '../services/tokens.js';
import { JWT_ALG, b64urlStr, verifySignature, buildJwk } from '../services/jwt.js';
import { oidcIssuer } from '../services/issuer.js';

const router = Router();

// --- Paths ----------------------------------------------------
const __dirname   = dirname(fileURLToPath(import.meta.url));
const TRUSTED_APP = resolve(__dirname, '../../signin.html');

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

/**
 * Express parses a repeated query/form key (?scope=a&scope=b) into an array.
 * Every OIDC parameter is single-valued, and the handlers below call string
 * methods on them, so a repeated key would surface as a 500. Reject it up
 * front with the error the spec has for a malformed request.
 */
function singleValued(req, res, next) {
  for (const src of [req.query, req.body]) {
    if (!src || typeof src !== 'object') continue;
    for (const [k, v] of Object.entries(src)) {
      if (v !== undefined && typeof v !== 'string') {
        return res.status(400).json({ error: 'invalid_request', error_description: `parameter ${k} must be a single string value` });
      }
    }
  }
  next();
}

/** RFC 6749 s.5.1/s.5.2: token responses (success and error) must not be cached. */
function noStore(_req, res, next) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
}

/**
 * Validate the scope, PKCE and OIDC request params shared by GET /authorize and
 * POST /authorize/login. The caller MUST have already validated client_id and
 * redirect_uri -- ordering is security-sensitive (an error must never touch an
 * unvalidated redirect_uri; open-redirect prevention, OAuth 2.0 s.4.1.2.1).
 * Returns a neutral { error, error_description? } or null when valid; the caller
 * chooses delivery (redirect via sendAuthError, or JSON 400).
 */
function validateAuthParams({ scope, code_challenge, code_challenge_method, nonce, state }, clientRaw) {
  const requestedScopes = (scope ?? '').split(' ').filter(Boolean);
  if (!requestedScopes.includes('openid')) return { error: 'invalid_scope' };
  const allowedScopes = JSON.parse(clientRaw.scopes ?? '["openid"]');
  if (!requestedScopes.every(s => allowedScopes.includes(s))) return { error: 'invalid_scope' };

  // PKCE is mandatory for a client that opted in AND for every public client
  // (no secret -- PKCE is the only thing binding the code to the requester).
  const pkceRequired = clientRaw.pkce === 'true' || clientRaw.public === 'true';
  if (pkceRequired && !code_challenge) {
    return { error: 'invalid_request', error_description: 'PKCE S256 required' };
  }
  // RFC 7636 s.4.3: a missing code_challenge_method means "plain", which this
  // OP does not support (Discovery says S256 only). Say so here, at the
  // authorization endpoint, instead of letting /token fail with invalid_grant.
  if (code_challenge && code_challenge_method !== 'S256') {
    return { error: 'invalid_request', error_description: 'code_challenge_method must be S256' };
  }

  const paramErr = validate(
    vNonce(nonce),
    vState(state),
    code_challenge ? vCodeChallenge(code_challenge) : null,
  );
  if (paramErr) return { error: 'invalid_request', error_description: paramErr };

  return null;
}

// --- 1. GET /.well-known/openid-configuration -----------------
export function discoveryHandler(_req, res) {
  const issuer = oidcIssuer();
  res.json({
    issuer,
    authorization_endpoint:                `${issuer}/authorize`,
    token_endpoint:                         `${issuer}/token`,
    userinfo_endpoint:                      `${issuer}/userinfo`,
    jwks_uri:                               `${issuer}/jwks.json`,
    end_session_endpoint:                   `${issuer}/logout`,
    scopes_supported:                       ['openid', 'email', 'profile'],
    response_types_supported:               ['code'],
    // Discovery 1.0 s.3 defaults would otherwise advertise implicit,
    // fragment responses and request_uri -- none of which exist here.
    grant_types_supported:                  ['authorization_code'],
    response_modes_supported:               ['query'],
    request_parameter_supported:            false,
    request_uri_parameter_supported:        false,
    claims_parameter_supported:             false,
    subject_types_supported:               ['public'],
    id_token_signing_alg_values_supported:  ['EdDSA', 'ES256', 'ES384', 'ES512'],
    userinfo_signing_alg_values_supported:  ['none'],
    // 'none' = public client (client.public=true): PKCE only, no secret.
    token_endpoint_auth_methods_supported:  ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported:       ['S256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
                       'name', 'email', 'email_verified', 'preferred_username'],
  });
}

// --- 2. GET /jwks.json ----------------------------------------
router.get('/jwks.json', singleValued, async (req, res, next) => {
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
router.get('/authorize', singleValued, async (req, res, next) => {
  try {
    const { client_id, redirect_uri, response_type, state } = req.query;

    // Validate client + redirect_uri FIRST -- an error must never be redirected
    // to an unvalidated redirect_uri (open-redirect prevention, OAuth 2.0 s.4.1.2.1).
    // These two are answered to the user agent directly (RFC 6749 s.4.1.2.1:
    // "inform the resource owner", never redirect) with the registry code for
    // a malformed request.
    const clientRaw = client_id ? await redis.hGetAll(`client:${client_id}`) : null;
    if (!clientRaw?.client_id) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'unknown client_id' });
    }

    const allowedRedirects = JSON.parse(clientRaw.redirect_uris ?? '[]');
    if (!redirect_uri || !allowedRedirects.includes(redirect_uri)) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is not registered for this client' });
    }

    // redirect_uri is now trusted -- subsequent errors may safely redirect to it.
    if (!response_type) {
      return sendAuthError(res, redirect_uri, 'invalid_request', state, 'response_type is required');
    }
    if (response_type !== 'code') {
      return sendAuthError(res, redirect_uri, 'unsupported_response_type', state);
    }

    const authErr = validateAuthParams(req.query, clientRaw);
    if (authErr) return sendAuthError(res, redirect_uri, authErr.error, state, authErr.error_description);

    res.sendFile(TRUSTED_APP);

  } catch (err) { next(err); }
});

// --- 4. POST /authorize/login ---------------------------------
router.post('/authorize/login',
  // Backstop keyed by IP -- the per-client_id limit below can be bypassed by
  // rotating client_id, but the caller cannot rotate their source IP as cheaply.
  rateLimit({ prefix: 'login-ip', max: 40, window: 60 }),
  rateLimit({ prefix: 'login', max: 20, window: 60,
    keyFn: req => (typeof req.body?.client_id === 'string' && req.body.client_id) || req.ip }),
  singleValued,
  async (req, res, next) => {
    try {
      const {
        sub: subParam, username, client_id, redirect_uri, scope,
        state, nonce, code_challenge, response_type,
      } = req.body;

      if (!response_type) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'response_type is required' });
      }
      if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type' });
      }

      const clientRaw = client_id ? await redis.hGetAll(`client:${client_id}`) : null;
      if (!clientRaw?.client_id) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'unknown client_id' });
      }

      const allowedRedirects = JSON.parse(clientRaw.redirect_uris ?? '[]');
      if (!redirect_uri || !allowedRedirects.includes(redirect_uri)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is not registered for this client' });
      }

      const authErr = validateAuthParams(req.body, clientRaw);
      if (authErr) return res.status(400).json(authErr);

      // Reused below when persisting the granted scope into the pending session.
      const requestedScopes = (scope ?? '').split(' ').filter(Boolean);

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

      // Authorization to this client: either the client is open to any enrolled
      // user (allow_any_user, opt-in per client), or the user was explicitly
      // granted it (clients[]). An open client still requires an existing,
      // enrolled Encedo user -- it never auto-creates the identity.
      const clientOpen = clientRaw.allow_any_user === 'true';
      const hasGrant   = !!user && JSON.parse(user.clients ?? '[]').includes(client_id);
      const authorized = clientOpen || hasGrant;

      // Unified error -- do not reveal whether user exists, is unauthorized, or incomplete
      if (!user || !authorized || !user.pubkey || !user.kid) {
        await logSecurity(SEC.LOGIN_FAIL, {
          client_id,
          hint: !user ? 'user_not_found' : !authorized ? 'client_not_authorized' : 'enrollment_incomplete',
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
        iss:                oidcIssuer(),
        sub:                user.sub,
        aud:                client_id,
        iat:                now,
        exp:                now + idTokenTtl,
        auth_time:          now,
        jti:                randomBytes(16).toString('base64url'),
        ...(nonce ? { nonce } : {}),
        email:              user.email,
        email_verified:     user.email_verified === 'true',
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
  singleValued,
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
// Client authentication (RFC 6749 s.3.2.1 / OIDC Core s.9): a confidential
// client -- every client unless registered with public=true -- MUST present its
// client_secret, via HTTP Basic or the request body. PKCE is verified IN
// ADDITION whenever the code carries a code_challenge; it never replaces the
// secret. (It used to: any code minted with a code_challenge skipped the
// secret check, so an attacker who planted their own challenge in the
// authorization link could redeem a leaked code without the secret.) A public
// client has no secret and is bound to the code by PKCE alone, which the
// authorization endpoint makes mandatory for it.
router.post('/token',
  rateLimit({ prefix: 'token', max: 20, window: 60 }),
  noStore,
  singleValued,
  async (req, res, next) => {
    try {
      let {
        grant_type, code, redirect_uri,
        client_id, client_secret, code_verifier,
      } = req.body;

      // Client credentials via HTTP Basic (RFC 6749 s.2.3.1): the two parts are
      // form-urlencoded before being joined with ':' and base64-encoded.
      const basicHeader = req.headers['authorization'];
      const usedBasic   = typeof basicHeader === 'string' && basicHeader.startsWith('Basic ');
      if (usedBasic) {
        const decoded = Buffer.from(basicHeader.slice(6), 'base64').toString();
        const colon   = decoded.indexOf(':');
        if (colon > 0) {
          try {
            client_id     = decodeURIComponent(decoded.slice(0, colon));
            client_secret = decodeURIComponent(decoded.slice(colon + 1));
          } catch {
            client_id = client_secret = undefined;
          }
        }
      }

      // RFC 6749 s.5.2: invalid_client is 401, and when the client used the
      // Authorization header the response carries a matching WWW-Authenticate.
      const invalidClient = (description) => {
        if (usedBasic) res.setHeader('WWW-Authenticate', 'Basic realm="token"');
        return res.status(401).json({ error: 'invalid_client', ...(description ? { error_description: description } : {}) });
      };

      if (!grant_type) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'grant_type is required' });
      }
      if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
      }
      if (!code) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'missing code' });
      }
      if (!client_id) {
        return invalidClient('client_id is required');
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
        return invalidClient();
      }

      // 1. Client authentication -- confidential clients always, regardless of PKCE.
      const isPublic = clientRaw.public === 'true';
      if (!isPublic) {
        if (!client_secret) {
          return invalidClient('client authentication required');
        }
        let match = false;
        try {
          const a = Buffer.from(client_secret);
          const b = Buffer.from(clientRaw.client_secret ?? '');
          match = a.length === b.length && timingSafeEqual(a, b);
        } catch { match = false; }
        if (!match) {
          return invalidClient();
        }
      } else if (!codeData.code_challenge) {
        // The authorization endpoint refuses a public client without PKCE, so
        // this is a defence in depth against a code minted some other way.
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE is required for a public client' });
      }

      // 2. PKCE -- whenever the code was bound to a challenge (RFC 7636 s.4.6).
      if (codeData.code_challenge) {
        if (!code_verifier) {
          return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier required' });
        }
        const verifierErr = vCodeVerifier(code_verifier);
        if (verifierErr) return res.status(400).json({ error: 'invalid_request', error_description: verifierErr });
        const expected = createHash('sha256').update(code_verifier).digest('base64url');
        let match = false;
        try {
          match = timingSafeEqual(Buffer.from(expected), Buffer.from(codeData.code_challenge));
        } catch { match = false; }
        if (!match) {
          return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier mismatch' });
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
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    const authHeader = req.headers['authorization'] ?? '';
    const token = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : (typeof req.body?.access_token === 'string' ? req.body.access_token : null);   // POST body fallback (RFC 6750 s.2.2)

    // RFC 6750 s.3: a request without credentials gets a bare challenge; one
    // with a bad token gets the challenge plus error="invalid_token".
    if (!token) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'invalid_token' });
    }
    const rejectToken = (description) => {
      res.setHeader('WWW-Authenticate', `Bearer error="invalid_token", error_description="${description}"`);
      return res.status(401).json({ error: 'invalid_token', error_description: description });
    };

    const sessionRaw = await redis.get(`access:${token}`);
    if (!sessionRaw) return rejectToken('token expired or not found');
    const session = JSON.parse(sessionRaw);

    const userRaw = await redis.hGetAll(`user:${session.sub}`);
    if (!userRaw?.sub) return rejectToken('user not found');

    const customClaims = JSON.parse(userRaw.custom_claims ?? '{}');
    const hsmUrlInUserinfo = userRaw.hsm_url_in_userinfo !== '0';

    res.json({
      sub:                userRaw.sub,
      name:               userRaw.name,
      email:              userRaw.email,
      email_verified:     userRaw.email_verified === 'true',
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
  singleValued,
  async (req, res, next) => {
    const { id_token_hint, post_logout_redirect_uri, state } = req.query;

    // Redirect to post_logout_redirect_uri ONLY when its origin is registered for
    // the client identified (and verified) via id_token_hint. Without a verified
    // hint we cannot identify the client, so we never redirect to an unvalidated
    // URI -- prevents open redirect (OIDC RP-Initiated Logout s.2).
    function finish(allowedOrigins = null) {
      if (post_logout_redirect_uri) {
        let url;
        try {
          url = new URL(post_logout_redirect_uri);
        } catch {
          return res.status(400).json({ error: 'invalid_request', error_description: 'invalid post_logout_redirect_uri' });
        }
        if (allowedOrigins?.includes(url.origin)) {
          if (state) url.searchParams.set('state', state);
          return res.redirect(url.toString());
        }
        // Not registered for a verified client -- do not open-redirect.
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
      const issuerCheck = oidcIssuer();
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
      const revokedTokens = await revokeUserTokens(sub);

      // Hint verified -- resolve which post-logout origins are allowed for this
      // client (origins of its registered redirect_uris). aud is the client_id.
      let allowedOrigins = null;
      try {
        const clientRaw = await redis.hGetAll(`client:${payload.aud}`);
        allowedOrigins = JSON.parse(clientRaw?.redirect_uris ?? '[]')
          .map(u => { try { return new URL(u).origin; } catch { return null; } })
          .filter(Boolean);
      } catch { allowedOrigins = null; }

      await logSecurity(SEC.LOGOUT, {
        sub, username: userRaw.username, result: 'ok', revokedTokens, ip: req.ip,
      });
      console.log(`[OIDC] Logout: revoked=${revokedTokens} tokens`);
      finish(allowedOrigins);

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
