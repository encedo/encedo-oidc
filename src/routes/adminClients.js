import { Router } from 'express';
import { randomUUID, randomBytes } from 'crypto';
import redis from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validate, vRequired, vTtl } from '../middleware/validate.js';

const router = Router();

// ─── Helpers ──────────────────────────────────────────────────
const ALLOWED_SCOPES = ['openid', 'profile', 'email', 'groups'];

function generateClientSecret() { return randomBytes(32).toString('base64url'); }
function generateClientId()     { return randomUUID(); }

function validateRedirectUris(uris) {
  for (const uri of uris) {
    try {
      const u = new URL(uri);
      if (u.protocol !== 'https:' && !(u.protocol === 'http:' && u.hostname === 'localhost')) {
        return `Non-localhost HTTP not allowed: ${uri}`;
      }
    } catch { return `Invalid URI: ${uri}`; }
  }
  return null;
}

function deserialize(raw) {
  if (!raw || Object.keys(raw).length === 0) return null;
  return {
    ...raw,
    redirect_uris:    JSON.parse(raw.redirect_uris    ?? '[]'),
    scopes:           JSON.parse(raw.scopes           ?? '["openid"]'),
    pkce:             raw.pkce === 'true',
    id_token_ttl:     parseInt(raw.id_token_ttl)     || 3600,
    access_token_ttl: parseInt(raw.access_token_ttl) || 3600,
  };
}

// ─── GET /admin/clients ───────────────────────────────────────
router.get('/', async (_req, res, next) => {
  try {
    const ids = await redis.sMembers('clients');
    if (!ids.length) return res.json([]);
    const pipeline = redis.multi();
    for (const id of ids) pipeline.hGetAll(`client:${id}`);
    const results = await pipeline.exec();
    res.json(
      results
        .map(deserialize)
        .filter(Boolean)
        .map(({ client_secret, ...safe }) => safe)   // strip secret from list
    );
  } catch (err) { next(err); }
});

// ─── GET /admin/clients/:id ───────────────────────────────────
router.get('/:id', async (req, res, next) => {
  try {
    const raw = await redis.hGetAll(`client:${req.params.id}`);
    const client = deserialize(raw);
    if (!client) return res.status(404).json({ error: 'client_not_found' });
    const { client_secret, ...safe } = client; // omit secret
    res.json(safe);
  } catch (err) { next(err); }
});

// ─── POST /admin/clients ──────────────────────────────────────
router.post('/', async (req, res, next) => {
  try {
    const {
      name, redirect_uris = [],
      scopes = ['openid', 'profile', 'email'],
      pkce = true,
      id_token_ttl = 3600,
      access_token_ttl = 3600,
    } = req.body ?? {};

    const err = validate(
      vRequired(name, 'name', 128),
      vTtl(id_token_ttl,     'id_token_ttl',     { min: 60, max: 86400 }),
      vTtl(access_token_ttl, 'access_token_ttl', { min: 60, max: 86400 }),
    );
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    if (!Array.isArray(redirect_uris) || !redirect_uris.length) {
      return res.status(400).json({ error: 'validation_error', error_description: 'redirect_uris must be a non-empty array' });
    }
    if (typeof pkce !== 'boolean') {
      return res.status(400).json({ error: 'validation_error', error_description: 'pkce must be a boolean' });
    }

    const uriErr = validateRedirectUris(redirect_uris);
    if (uriErr) return res.status(400).json({ error: 'validation_error', error_description: uriErr });

    const validScopes = scopes.filter(s => ALLOWED_SCOPES.includes(s));
    if (!validScopes.includes('openid')) validScopes.unshift('openid');

    const client_id     = generateClientId();
    const client_secret = generateClientSecret();

    const record = {
      client_id,
      client_secret,
      name:             name.trim(),
      redirect_uris:    JSON.stringify(redirect_uris),
      scopes:           JSON.stringify(validScopes),
      pkce:             String(pkce),
      id_token_ttl:     String(id_token_ttl),
      access_token_ttl: String(access_token_ttl),
      created_at:       new Date().toISOString(),
    };

    await redis.hSet(`client:${client_id}`, record);
    await redis.sAdd('clients', client_id);

    await logSecurity(SEC.ADMIN_CLIENT_CREATE, { client_id, name, ip: req.ip });
    console.log(`[Admin] Client created: ${client_id} (${name})`);
    // return with secret — only time it's visible
    res.status(201).json({ ...deserialize(record), client_secret });
  } catch (err) { next(err); }
});

// ─── PATCH /admin/clients/:id ─────────────────────────────────
router.patch('/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const exists = await redis.sIsMember('clients', id);
    if (!exists) return res.status(404).json({ error: 'client_not_found' });

    const updates = {};

    if (req.body.name !== undefined) {
      const e = vRequired(req.body.name, 'name', 128);
      if (e) return res.status(400).json({ error: 'validation_error', error_description: e });
      updates.name = req.body.name.trim();
    }

    if (Array.isArray(req.body.redirect_uris)) {
      const e = validateRedirectUris(req.body.redirect_uris);
      if (e) return res.status(400).json({ error: 'validation_error', error_description: e });
      updates.redirect_uris = JSON.stringify(req.body.redirect_uris);
    }

    if (Array.isArray(req.body.scopes)) {
      const valid = req.body.scopes.filter(s => ALLOWED_SCOPES.includes(s));
      if (!valid.includes('openid')) valid.unshift('openid');
      updates.scopes = JSON.stringify(valid);
    }

    if (req.body.pkce !== undefined) {
      if (typeof req.body.pkce !== 'boolean') {
        return res.status(400).json({ error: 'validation_error', error_description: 'pkce must be a boolean' });
      }
      updates.pkce = String(req.body.pkce);
    }

    if (req.body.id_token_ttl !== undefined) {
      const e = vTtl(req.body.id_token_ttl, 'id_token_ttl', { min: 60, max: 86400 });
      if (e) return res.status(400).json({ error: 'validation_error', error_description: e });
      updates.id_token_ttl = String(parseInt(req.body.id_token_ttl, 10));
    }

    if (req.body.access_token_ttl !== undefined) {
      const e = vTtl(req.body.access_token_ttl, 'access_token_ttl', { min: 60, max: 86400 });
      if (e) return res.status(400).json({ error: 'validation_error', error_description: e });
      updates.access_token_ttl = String(parseInt(req.body.access_token_ttl, 10));
    }

    if (Object.keys(updates).length === 0)
      return res.status(400).json({ error: 'no_valid_fields' });

    await redis.hSet(`client:${id}`, updates);
    await logSecurity(SEC.ADMIN_CLIENT_CREATE, { client_id: id, fields: Object.keys(updates), ip: req.ip });
    const { client_secret, ...safe } = deserialize(await redis.hGetAll(`client:${id}`));
    res.json(safe);
  } catch (err) { next(err); }
});

// ─── POST /admin/clients/:id/rotate-secret ────────────────────
router.post('/:id/rotate-secret', async (req, res, next) => {
  try {
    const { id } = req.params;
    const exists = await redis.sIsMember('clients', id);
    if (!exists) return res.status(404).json({ error: 'client_not_found' });

    const client_secret = generateClientSecret();
    await redis.hSet(`client:${id}`, { client_secret });

    await logSecurity(SEC.ADMIN_SECRET_ROTATE, { client_id: id, ip: req.ip });
    console.log(`[Admin] Secret rotated for client: ${id}`);
    res.json({ client_id: id, client_secret });
  } catch (err) { next(err); }
});

// ─── DELETE /admin/clients/:id ────────────────────────────────
router.delete('/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const exists = await redis.sIsMember('clients', id);
    if (!exists) return res.status(404).json({ error: 'client_not_found' });

    await redis.del(`client:${id}`);
    await redis.sRem('clients', id);

    await logSecurity(SEC.ADMIN_CLIENT_DELETE, { client_id: id, ip: req.ip });
    console.log(`[Admin] Client deleted: ${id}`);
    res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
