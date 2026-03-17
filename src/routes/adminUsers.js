import { Router } from 'express';
import { randomUUID, randomBytes } from 'crypto';
import redis from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validate, vEmail, vUrl, vUsername, vDisplayName, vUuid } from '../middleware/validate.js';

const router = Router();

function deserialize(raw) {
  if (!raw || Object.keys(raw).length === 0) return null;
  return {
    ...raw,
    clients: JSON.parse(raw.clients ?? '[]'),
  };
}

// ─── GET /admin/users ─────────────────────────────────────────
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

// ─── GET /admin/users/:sub ────────────────────────────────────
router.get('/:sub', async (req, res, next) => {
  try {
    const raw = await redis.hGetAll(`user:${req.params.sub}`);
    const user = deserialize(raw);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    res.json(user);
  } catch (err) { next(err); }
});

// ─── POST /admin/users ────────────────────────────────────────
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

    // username must be unique
    const subs     = await redis.sMembers('users');
    const pipeline = redis.multi();
    for (const s of subs) pipeline.hGet(`user:${s}`, 'username');
    const existing = await pipeline.exec();
    if (existing.some(u => u === username.trim())) {
      return res.status(409).json({ error: 'username_already_exists' });
    }

    const sub = randomUUID();

    const record = {
      sub,
      username:   username.trim(),
      name:       (name ?? '').trim(),
      email:      email.trim().toLowerCase(),
      hsm_url:    hsm_url.trim(),
      clients:    '[]',
      created_at: new Date().toISOString(),
    };

    await redis.hSet(`user:${sub}`, record);
    await redis.sAdd('users', sub);

    // Generate enrollment link (24h) — included in creation response
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
    res.status(201).json({ ...deserialize({ ...record, enrollment_token: token }), enrollment_url });
  } catch (err) { next(err); }
});

// ─── PATCH /admin/users/:sub ──────────────────────────────────
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

    updates.updated_at = new Date().toISOString();
    await redis.hSet(`user:${sub}`, updates);
    await logSecurity(SEC.ADMIN_USER_PATCH, { sub, fields: Object.keys(updates), ip: req.ip });
    res.json(deserialize(await redis.hGetAll(`user:${sub}`)));
  } catch (err) { next(err); }
});

// ─── DELETE /admin/users/:sub ─────────────────────────────────
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

    await redis.del(`user:${sub}`);
    await redis.sRem('users', sub);

    await logSecurity(SEC.ADMIN_USER_DELETE, { sub, revokedTokens: tokenKeys.length, ip: req.ip });
    console.log(`[Admin] User deleted: ${sub}`);
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
