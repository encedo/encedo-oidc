import { randomBytes, randomUUID } from 'crypto';
import redis              from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { vRequired }     from '../middleware/validate.js';

const ALLOWED_SCOPES = ['openid', 'profile', 'email'];
const issuer = () => process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;

function generateClientSecret() { return randomBytes(32).toString('base64url'); }

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

// --- POST /admin/invite-client --------------------------------
export async function adminInviteClientHandler(req, res, next) {
  try {
    const { note } = req.body ?? {};
    const token = randomBytes(32).toString('hex');
    await redis.set(`client-invite:${token}`, JSON.stringify({
      note: note?.trim() ?? '',
    }), { EX: 86400 });

    const invite_url = `${issuer()}/signup-client#token=${token}`;
    await logSecurity(SEC.ADMIN_CLIENT_CREATE, { action: 'client_invite_generated', ip: req.ip });
    res.status(201).json({ invite_url, expires_in: 86400 });
  } catch (err) { next(err); }
}

// --- DELETE /admin/client-invites/:token ----------------------
export async function adminDeleteClientInviteHandler(req, res, next) {
  try {
    const { token } = req.params;
    const deleted = await redis.del(`client-invite:${token}`);
    if (!deleted) return res.status(404).json({ error: 'invite_not_found' });
    res.status(204).send();
  } catch (err) { next(err); }
}

// --- GET /signup-client/prefill?token= ------------------------
export async function signupClientPrefillHandler(req, res, next) {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token_required' });
    const raw = await redis.get(`client-invite:${token}`);
    if (!raw) return res.status(404).json({ error: 'invite_not_found_or_expired' });
    res.json({ ok: true });
  } catch (err) { next(err); }
}

// --- POST /signup-client/register -----------------------------
export async function signupClientRegisterHandler(req, res, next) {
  try {
    const { token, name, redirect_uris, scopes, pkce } = req.body ?? {};

    if (!token) return res.status(400).json({ error: 'token_required' });
    const raw = await redis.get(`client-invite:${token}`);
    if (!raw) return res.status(404).json({ error: 'invite_not_found_or_expired' });

    const nameErr = vRequired(name, 'name', 128);
    if (nameErr) return res.status(400).json({ error: 'validation_error', error_description: nameErr });

    if (!Array.isArray(redirect_uris) || !redirect_uris.length) {
      return res.status(400).json({ error: 'validation_error', error_description: 'redirect_uris must be a non-empty array' });
    }
    const uriErr = validateRedirectUris(redirect_uris);
    if (uriErr) return res.status(400).json({ error: 'validation_error', error_description: uriErr });

    const validScopes = Array.isArray(scopes)
      ? scopes.filter(s => ALLOWED_SCOPES.includes(s))
      : ['openid', 'profile', 'email'];
    if (!validScopes.includes('openid')) validScopes.unshift('openid');

    const pkceEnabled = pkce !== false;

    const client_id     = randomUUID();
    const client_secret = generateClientSecret();

    const record = {
      client_id,
      client_secret,
      name:             name.trim(),
      redirect_uris:    JSON.stringify(redirect_uris),
      scopes:           JSON.stringify(validScopes),
      pkce:             String(pkceEnabled),
      id_token_ttl:     '3600',
      access_token_ttl: '3600',
      created_at:       new Date().toISOString(),
    };

    await redis.hSet(`client:${client_id}`, record);
    await redis.sAdd('clients', client_id);

    // Consume invite — one-time use
    await redis.del(`client-invite:${token}`);

    await logSecurity(SEC.ADMIN_CLIENT_CREATE, { action: 'signup', client_id, name: name.trim(), ip: req.ip });
    res.status(201).json({ client_id, client_secret, name: name.trim() });
  } catch (err) { next(err); }
}
