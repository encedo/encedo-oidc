import { Router } from 'express';
import { randomUUID, randomBytes } from 'crypto';
import redis from '../services/redis.js';

const AUDIT_ZSET = 'security:log';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validate, vEmail, vUrl, vUsername, vDisplayName, vUuid, vClaimKey, vOptional, vKeyType } from '../middleware/validate.js';

const DEFAULT_KEY_TYPE = 'Ed25519';

const router = Router();

function deserialize(raw) {
  if (!raw || Object.keys(raw).length === 0) return null;
  // eslint-disable-next-line no-unused-vars
  const { enrollment_token, ...rest } = raw; // internal field -- never exposed via API
  return {
    ...rest,
    clients:              JSON.parse(rest.clients       ?? '[]'),
    custom_claims:        JSON.parse(rest.custom_claims ?? '{}'),
    hsm_url_in_userinfo:  rest.hsm_url_in_userinfo !== '0', // default true
  };
}

// --- GET /admin/users -----------------------------------------
router.get('/', async (_req, res, next) => {
  try {
    const subs = await redis.sMembers('users');
    if (subs.length === 0) return res.json([]);

    const pipeline = redis.multi();
    for (const sub of subs) pipeline.hGetAll(`user:${sub}`);
    const results = await pipeline.exec();

    res.json(results.map(deserialize).filter(Boolean));
  } catch (err) { next(err); }
});

// --- GET /admin/users/:sub ------------------------------------
router.get('/:sub', async (req, res, next) => {
  try {
    const raw = await redis.hGetAll(`user:${req.params.sub}`);
    const user = deserialize(raw);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    res.json(user);
  } catch (err) { next(err); }
});

// --- POST /admin/users ----------------------------------------
router.post('/', async (req, res, next) => {
  try {
    const { username, name, email, hsm_url, key_type } = req.body ?? {};

    const err = validate(
      vUsername(username),
      vEmail(email),
      vUrl(hsm_url, 'hsm_url', { httpsOnly: true, allowLocalhost: true }),
      vDisplayName(name),
      vKeyType(key_type),
    );
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    const resolvedKeyType = key_type ?? DEFAULT_KEY_TYPE;

    // username must be unique -- O(1) index lookup
    const uname = username.trim();
    if (await redis.hGet('username_index', uname)) {
      return res.status(409).json({ error: 'username_already_exists' });
    }

    const sub = randomUUID();

    const record = {
      sub,
      username:   uname,
      name:       (name ?? '').trim(),
      email:      email.trim().toLowerCase(),
      hsm_url:    hsm_url.trim(),
      clients:    '[]',
      created_at: new Date().toISOString(),
    };

    await redis.hSet(`user:${sub}`, record);
    await redis.sAdd('users', sub);
    await redis.hSet('username_index', uname, sub);

    // Generate enrollment link (24h) -- included in creation response
    const token = randomBytes(32).toString('base64url');
    await redis.set(`enrollment:${token}`, JSON.stringify({
      sub,
      username:        record.username,
      forced_key_type: resolvedKeyType,
    }), { EX: 86400 });
    await redis.hSet(`user:${sub}`, { enrollment_token: token });

    const issuer = process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;
    // Fragment (#) keeps token out of server access logs and Referer headers
    const enrollment_url = `${issuer}/enrollment#token=${token}`;

    await logSecurity(SEC.ADMIN_USER_CREATE, { sub, username, ip: req.ip });
    console.log(`[Admin] User created: ${sub} (${username})`);
    // enrollment_token stripped by deserialize -- only enrollment_url returned
    res.status(201).json({ ...deserialize({ ...record, enrollment_token: token }), enrollment_url });
  } catch (err) { next(err); }
});

// --- PATCH /admin/users/:sub ----------------------------------
router.patch('/:sub', async (req, res, next) => {
  try {
    const { sub } = req.params;
    const exists = await redis.sIsMember('users', sub);
    if (!exists) return res.status(404).json({ error: 'user_not_found' });

    // Validate each present field
    const checks = [];
    if (req.body.username !== undefined) checks.push(vUsername(req.body.username));
    if (req.body.email    !== undefined) checks.push(vEmail(req.body.email));
    if (req.body.hsm_url  !== undefined) checks.push(vUrl(req.body.hsm_url, 'hsm_url', { httpsOnly: true, allowLocalhost: true }));
    if (req.body.name     !== undefined) checks.push(vDisplayName(req.body.name));
    if (req.body.clients  !== undefined) {
      if (!Array.isArray(req.body.clients)) {
        checks.push('clients must be an array');
      } else {
        for (const id of req.body.clients) {
          const e = vUuid(id, `clients[${id}]`);
          if (e) { checks.push(e); break; }
        }
      }
    }

    const err = checks.find(e => e !== null && e !== undefined) ?? null;
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    const allowed = ['username', 'name', 'email', 'hsm_url'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        updates[key] = key === 'email'
          ? req.body[key].trim().toLowerCase()
          : req.body[key];
      }
    }

    if (Array.isArray(req.body.clients)) {
      updates.clients = JSON.stringify(req.body.clients);
    }

    if (req.body.hsm_url_in_userinfo !== undefined) {
      updates.hsm_url_in_userinfo = req.body.hsm_url_in_userinfo ? '1' : '0';
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'no_valid_fields' });
    }

    // If renaming username: atomically claim new name before releasing old one
    if (updates.username) {
      const newName    = updates.username.trim();
      const currentRaw = await redis.hGet(`user:${sub}`, 'username');

      if (currentRaw !== newName) {
        // HSETNX: set only if field doesn't exist -- atomic, no race window
        const claimed = await redis.hSetNX('username_index', newName, sub);
        if (!claimed) {
          // Field existed -- check if it's owned by this sub (idempotent rename)
          const owner = await redis.hGet('username_index', newName);
          if (owner !== sub) {
            return res.status(409).json({ error: 'username_already_exists' });
          }
        }
        if (currentRaw) await redis.hDel('username_index', currentRaw);
      }
      updates.username = newName;
    }

    updates.updated_at = new Date().toISOString();
    await redis.hSet(`user:${sub}`, updates);
    await logSecurity(SEC.ADMIN_USER_PATCH, { sub, username: updates.username ?? await redis.hGet(`user:${sub}`, 'username'), fields: Object.keys(updates), ip: req.ip });
    res.json(deserialize(await redis.hGetAll(`user:${sub}`)));
  } catch (err) { next(err); }
});

// --- POST /admin/users/:sub/enrollment -----------------------
// Generates a new enrollment token (invalidates previous).
// Works whether user is already enrolled or not -- overwrites pubkey+kid on completion.
router.post('/:sub/enrollment', async (req, res, next) => {
  try {
    const { sub } = req.params;
    const raw = await redis.hGetAll(`user:${sub}`);
    const user = deserialize(raw);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const { key_type } = req.body ?? {};
    const ktErr = vKeyType(key_type);
    if (ktErr) return res.status(400).json({ error: 'validation_error', error_description: ktErr });
    // If not specified, preserve existing key_type or fall back to default
    const resolvedKeyType = key_type ?? raw.key_type ?? DEFAULT_KEY_TYPE;

    // Invalidate previous enrollment token if present
    if (raw.enrollment_token) {
      await redis.del(`enrollment:${raw.enrollment_token}`);
    }

    const token = randomBytes(32).toString('base64url');
    await redis.set(`enrollment:${token}`, JSON.stringify({
      sub,
      username:        raw.username,
      forced_key_type: resolvedKeyType,
    }), { EX: 86400 });
    await redis.hSet(`user:${sub}`, { enrollment_token: token });

    const issuer = process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;
    const enrollment_url = `${issuer}/enrollment#token=${token}`;

    await logSecurity(SEC.ENROLL_REGEN, { sub, username: raw.username, ip: req.ip });
    res.json({ enrollment_url });
  } catch (err) { next(err); }
});

// --- GET /admin/users/:sub/claims -----------------------------
router.get('/:sub/claims', async (req, res, next) => {
  try {
    const raw = await redis.hGetAll(`user:${req.params.sub}`);
    if (!raw?.sub) return res.status(404).json({ error: 'user_not_found' });
    res.json({
      custom_claims:       JSON.parse(raw.custom_claims ?? '{}'),
      hsm_url_in_userinfo: raw.hsm_url_in_userinfo !== '0',
    });
  } catch (err) { next(err); }
});

// --- PUT /admin/users/:sub/claims -----------------------------
// Replace entire custom_claims object.
router.put('/:sub/claims', async (req, res, next) => {
  try {
    const { sub } = req.params;
    const exists = await redis.sIsMember('users', sub);
    if (!exists) return res.status(404).json({ error: 'user_not_found' });

    const { custom_claims, hsm_url_in_userinfo } = req.body ?? {};

    if (custom_claims !== undefined) {
      if (typeof custom_claims !== 'object' || Array.isArray(custom_claims)) {
        return res.status(400).json({ error: 'validation_error', error_description: 'custom_claims must be an object' });
      }
      for (const [k, v] of Object.entries(custom_claims)) {
        const ke = vClaimKey(k);
        if (ke) return res.status(400).json({ error: 'validation_error', error_description: ke });
        const ve = vOptional(String(v), k, 256);
        if (ve) return res.status(400).json({ error: 'validation_error', error_description: ve });
      }
    }

    const updates = { updated_at: new Date().toISOString() };
    if (custom_claims !== undefined)       updates.custom_claims        = JSON.stringify(custom_claims);
    if (hsm_url_in_userinfo !== undefined) updates.hsm_url_in_userinfo  = hsm_url_in_userinfo ? '1' : '0';

    await redis.hSet(`user:${sub}`, updates);
    const raw = await redis.hGetAll(`user:${sub}`);
    res.json({
      custom_claims:       JSON.parse(raw.custom_claims ?? '{}'),
      hsm_url_in_userinfo: raw.hsm_url_in_userinfo !== '0',
    });
  } catch (err) { next(err); }
});

// --- DELETE /admin/users/:sub ---------------------------------
router.delete('/:sub', async (req, res, next) => {
  try {
    const { sub } = req.params;
    const exists = await redis.sIsMember('users', sub);
    if (!exists) return res.status(404).json({ error: 'user_not_found' });

    // Revoke all active access tokens for this user
    const tokenKeys = await redis.sMembers(`user_tokens:${sub}`);
    if (tokenKeys.length > 0) {
      const pipeline = redis.multi();
      for (const k of tokenKeys) pipeline.del(k);
      pipeline.del(`user_tokens:${sub}`);
      await pipeline.exec();
    }

    const [username, enrollToken] = await Promise.all([
      redis.hGet(`user:${sub}`, 'username'),
      redis.hGet(`user:${sub}`, 'enrollment_token'),
    ]);
    if (enrollToken) await redis.del(`enrollment:${enrollToken}`);
    await redis.del(`user:${sub}`);
    await redis.sRem('users', sub);
    if (username) await redis.hDel('username_index', username);

    await logSecurity(SEC.ADMIN_USER_DELETE, { sub, username, revokedTokens: tokenKeys.length, ip: req.ip });
    console.log(`[Admin] User deleted: ${sub}`);
    res.status(204).send();
  } catch (err) { next(err); }
});

// --- GET /admin/audit-log -------------------------------------
export async function getAuditLog(req, res, next) {
  try {
    const limit  = Math.min(Math.max(parseInt(req.query.limit  ?? '20', 10), 1), 500);
    const offset = Math.max(parseInt(req.query.offset ?? '0', 10), 0);

    const [raw, total] = await Promise.all([
      redis.zRange(AUDIT_ZSET, '+inf', '-inf', {
        BY: 'SCORE', REV: true,
        LIMIT: { offset, count: limit },
      }),
      redis.zCard(AUDIT_ZSET),
    ]);

    const entries = raw.map(e => JSON.parse(e));
    res.json({ entries, total, offset, limit });
  } catch (err) { next(err); }
}

export default router;
