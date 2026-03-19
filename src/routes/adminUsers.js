import { Router } from 'express';
import { randomUUID, randomBytes } from 'crypto';
import redis from '../services/redis.js';

const AUDIT_ZSET = 'security:log';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validate, vEmail, vUrl, vUsername, vDisplayName, vUuid } from '../middleware/validate.js';

const router = Router();

function deserialize(raw) {
  if (!raw || Object.keys(raw).length === 0) return null;
  // eslint-disable-next-line no-unused-vars
  const { enrollment_token, ...rest } = raw; // internal field -- never exposed via API
  return {
    ...rest,
    clients: JSON.parse(rest.clients ?? '[]'),
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
    const { username, name, email, hsm_url } = req.body ?? {};

    const err = validate(
      vUsername(username),
      vEmail(email),
      vUrl(hsm_url, 'hsm_url', { httpsOnly: true, allowLocalhost: true }),
      vDisplayName(name),
    );
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

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
      username: record.username,
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

    // Invalidate previous enrollment token if present
    if (raw.enrollment_token) {
      await redis.del(`enrollment:${raw.enrollment_token}`);
    }

    const token = randomBytes(32).toString('base64url');
    await redis.set(`enrollment:${token}`, JSON.stringify({
      sub,
      username: raw.username,
    }), { EX: 86400 });
    await redis.hSet(`user:${sub}`, { enrollment_token: token });

    const issuer = process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;
    const enrollment_url = `${issuer}/enrollment#token=${token}`;

    await logSecurity(SEC.ENROLL_REGEN, { sub, username: raw.username, ip: req.ip });
    res.json({ enrollment_url });
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
