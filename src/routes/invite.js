import { randomBytes, randomUUID } from 'crypto';
import redis              from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validate, vEmail, vUsername, vDisplayName, vUrl, vKeyType } from '../middleware/validate.js';

const DEFAULT_KEY_TYPE = 'Ed25519';

const issuer = () => process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;

// Invite tokens: randomBytes(32).toString('hex') = 64 hex chars
const TOKEN_RE = /^[a-f0-9]{64}$/;

// --- POST /admin/invite ---------------------------------------
export async function adminInviteHandler(req, res, next) {
  try {
    const { client_id, username, name, email, key_type } = req.body ?? {};

    if (!client_id) {
      return res.status(400).json({ error: 'validation_error', error_description: 'client_id is required' });
    }
    const clientRaw = await redis.hGetAll(`client:${client_id}`);
    if (!clientRaw?.client_id) {
      return res.status(404).json({ error: 'client_not_found' });
    }

    const checks = [];
    if (username !== undefined) checks.push(vUsername(username));
    if (name     !== undefined) checks.push(vDisplayName(name));
    if (email    !== undefined) checks.push(vEmail(email));
    checks.push(vKeyType(key_type));
    const err = checks.find(e => e) ?? null;
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    const token = randomBytes(32).toString('hex');
    await redis.set(`invite:${token}`, JSON.stringify({
      client_id,
      client_name: clientRaw.name || client_id,
      username:    username?.trim() ?? '',
      name:        name?.trim()     ?? '',
      email:       email?.trim().toLowerCase() ?? '',
      key_type:    key_type ?? null, // null = user can choose during enrollment
    }), { EX: 86400 });

    const invite_url = `${issuer()}/signup#token=${token}`;
    await logSecurity(SEC.ADMIN_USER_CREATE, { action: 'invite_generated', client_id, ip: req.ip });

    res.status(201).json({ invite_url, expires_in: 86400 });
  } catch (err) { next(err); }
}

// --- GET /signup/prefill?token=... ----------------------------
export async function signupPrefillHandler(req, res, next) {
  try {
    const { token } = req.query;
    if (!token || !TOKEN_RE.test(token)) {
      return res.status(400).json({ error: 'invalid_token' });
    }

    const raw = await redis.get(`invite:${token}`);
    if (!raw) return res.status(404).json({ error: 'invite_not_found_or_expired' });

    const data = JSON.parse(raw);
    res.json({
      client_name: data.client_name,
      username:    data.username,
      name:        data.name,
      email:       data.email,
      key_type:    data.key_type ?? null, // null = user chooses during enrollment
    });
  } catch (err) { next(err); }
}

// --- GET /admin/invites ---------------------------------------
async function scanKeys(pattern) {
  const keys = [];
  let cursor = 0;
  do {
    const result = await redis.scan(cursor, { MATCH: pattern, COUNT: 100 });
    cursor = Number(result.cursor);
    keys.push(...result.keys);
  } while (cursor !== 0);
  return keys;
}

export async function adminListInvitesHandler(_req, res, next) {
  try {
    const [userKeys, clientKeys] = await Promise.all([
      scanKeys('invite:*'),
      scanKeys('client-invite:*'),
    ]);

    const allKeys = [
      ...userKeys.map(k => ({ key: k, type: 'user',   prefix: 'invite:' })),
      ...clientKeys.map(k => ({ key: k, type: 'client', prefix: 'client-invite:' })),
    ];

    if (allKeys.length === 0) return res.json([]);

    const pipeline = redis.multi();
    for (const { key } of allKeys) {
      pipeline.get(key);
      pipeline.ttl(key);
    }
    const results = await pipeline.exec();

    const invites = [];
    for (let i = 0; i < allKeys.length; i++) {
      const { key, type, prefix } = allKeys[i];
      const raw = results[i * 2];
      const ttl = results[i * 2 + 1];
      if (!raw) continue;
      const data = JSON.parse(raw);
      const token = key.slice(prefix.length);
      invites.push({
        token,
        type,
        client_id:   data.client_id   ?? null,
        client_name: data.client_name ?? data.note ?? '',
        username:    data.username    ?? '',
        email:       data.email       ?? '',
        ttl,
      });
    }
    res.json(invites);
  } catch (err) { next(err); }
}

// --- DELETE /admin/invites/:token -----------------------------
export async function adminDeleteInviteHandler(req, res, next) {
  try {
    const { token } = req.params;
    const deleted = await redis.del(`invite:${token}`);
    if (!deleted) return res.status(404).json({ error: 'invite_not_found' });
    res.status(204).send();
  } catch (err) { next(err); }
}

// --- POST /signup/register ------------------------------------
// Called only after HSM is verified (checkin + authorize succeed).
// Creates user account + enrollment token; enrollment is completed
// by the frontend using the returned token (no redirect needed).
export async function signupRegisterHandler(req, res, next) {
  try {
    const { token, username, name, email, hsm_url, key_type: reqKeyType } = req.body ?? {};

    if (!token || !TOKEN_RE.test(token)) {
      return res.status(400).json({ error: 'invalid_token' });
    }

    // Validate inputs before consuming invite — so a validation error doesn't burn the token
    const err = validate(
      vUsername(username),
      vEmail(email),
      vDisplayName(name),
      vUrl(hsm_url, 'hsm_url', { httpsOnly: true, allowLocalhost: true }),
    );
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    const uname = username.trim();
    if (await redis.hGet('username_index', uname)) {
      return res.status(409).json({ error: 'username_already_exists' });
    }

    // Atomically consume invite — prevents race condition (two concurrent requests with same token)
    const raw = await redis.getDel(`invite:${token}`);
    if (!raw) return res.status(404).json({ error: 'invite_not_found_or_expired' });
    const invite = JSON.parse(raw);

    // Derive client redirect origin for post-enrollment Close button
    const clientRaw = await redis.hGetAll(`client:${invite.client_id}`);
    const redirectUris = JSON.parse(clientRaw?.redirect_uris ?? '[]');
    let client_redirect_origin = null;
    if (redirectUris.length) {
      try { client_redirect_origin = new URL(redirectUris[0]).origin; } catch { /* ignore */ }
    }

    const sub = randomUUID();
    const record = {
      sub,
      username:   uname,
      name:       (name ?? '').trim(),
      email:      email.trim().toLowerCase(),
      hsm_url:    hsm_url.trim(),
      clients:    JSON.stringify([invite.client_id]),
      created_at: new Date().toISOString(),
    };

    await redis.hSet(`user:${sub}`, record);
    await redis.sAdd('users', sub);
    await redis.hSet('username_index', uname, sub);

    // key_type priority: invite-forced > user-choice > default
    const forcedKeyType = invite.key_type ?? reqKeyType ?? DEFAULT_KEY_TYPE;

    const enrollToken = randomBytes(32).toString('base64url');
    await redis.set(`enrollment:${enrollToken}`, JSON.stringify({
      sub,
      username:          uname,
      hsm_url:           hsm_url.trim(),
      forced_key_type:   forcedKeyType,
      client_redirect_origin,
    }), { EX: 3600 }); // 1h — user is actively enrolling right now
    await redis.hSet(`user:${sub}`, { enrollment_token: enrollToken });

    await logSecurity(SEC.ADMIN_USER_CREATE, { action: 'signup', sub, username: uname, client_id: invite.client_id, ip: req.ip });

    res.status(201).json({
      sub,
      enrollment_token: enrollToken,
      client_redirect_origin,
    });
  } catch (err) { next(err); }
}
