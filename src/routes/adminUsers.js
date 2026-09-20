import { Router } from 'express';
import { randomUUID, randomBytes } from 'crypto';
import redis from '../services/redis.js';
import { resolveClientGrant } from '../services/clientGrant.js';
import { sendVerificationEmailHandler } from './emailVerify.js';
import { issuer } from '../services/issuer.js';
import { revokeUserTokens } from '../services/tokens.js';

const AUDIT_ZSET = 'security:log';
import { logSecurity, SEC } from '../services/securityLog.js';
import { invalidateJwksCache } from './oidc.js';
import { validate, vEmail, vUrl, vUsername, vDisplayName, vUuid, vClaimKey, vOptional, vKeyType } from '../middleware/validate.js';

const DEFAULT_KEY_TYPE = 'Ed25519';

const router = Router();

function deserialize(raw) {
  if (!raw || Object.keys(raw).length === 0) return null;
  const { enrollment_token, ...rest } = raw; // internal field -- never exposed via API (omitted here)
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
    const { username, name, email, hsm_url, key_type, clients } = req.body ?? {};

    const checks = [
      vUsername(username),
      vEmail(email),
      vUrl(hsm_url, 'hsm_url', { httpsOnly: true, allowLocalhost: true }),
      vDisplayName(name),
      vKeyType(key_type),
    ];

    // clients is optional; same shape as PATCH (array of client_id UUIDs). A user
    // with none cannot authenticate anywhere -- /authorize/login rejects them with
    // client_not_authorized -- so it was previously impossible to create a usable
    // user in one step.
    if (clients !== undefined) {
      if (!Array.isArray(clients)) {
        checks.push('clients must be an array');
      } else {
        for (const id of clients) {
          const e = vUuid(id, `clients[${id}]`);
          if (e) { checks.push(e); break; }
        }
      }
    }

    const err = validate(...checks);
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    // Every granted client must exist -- a well-formed UUID is not enough.
    const grant = await resolveClientGrant(clients);
    if (grant.unknown.length) {
      return res.status(400).json({ error: 'validation_error',
        error_description: `unknown client_id: ${grant.unknown.join(', ')}` });
    }

    const resolvedKeyType = key_type ?? DEFAULT_KEY_TYPE;

    // username + email must be unique -- O(1) index lookups. Uniqueness is scoped
    // to this tenant (one Redis per tenant). Pre-existing records were never
    // indexed and are grandfathered: this only prevents NEW collisions.
    const uname  = username.trim();
    const nemail = email.trim().toLowerCase();
    const sub = randomUUID();

    // Claim both index entries with HSETNX (atomic): two concurrent creates
    // with the same username or email cannot both pass a check-then-set.
    if (!(await redis.hSetNX('username_index', uname, sub))) {
      return res.status(409).json({ error: 'username_already_exists' });
    }
    if (!(await redis.hSetNX('email_index', nemail, sub))) {
      await redis.hDel('username_index', uname);
      return res.status(409).json({ error: 'email_already_exists' });
    }

    const record = {
      sub,
      username:   uname,
      name:       (name ?? '').trim(),
      email:      nemail,
      hsm_url:    hsm_url.trim(),
      clients:    JSON.stringify(grant.ids),
      email_verified: 'false',   // on-site Add: no mailbox proof; upgraded only via emailed link
      created_at: new Date().toISOString(),
    };

    // Enrollment link (24h) -- included in the creation response. One MULTI
    // for the hash, the set and the token: a SIGTERM or a dropped connection
    // halfway can no longer leave a user hash that is in no list (invisible
    // in the panel) while its username is already claimed.
    const token = randomBytes(32).toString('base64url');
    await redis.multi()
      .hSet(`user:${sub}`, { ...record, enrollment_token: token })
      .sAdd('users', sub)
      .set(`enrollment:${token}`, JSON.stringify({
        sub,
        username:        record.username,
        forced_key_type: resolvedKeyType,
      }), { EX: 86400 })
      .exec();

    // Fragment (#) keeps token out of server access logs and Referer headers
    const enrollment_url = `${issuer()}/enrollment#token=${token}`;

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

    // Every granted client must exist -- same rule as POST, so there is no path
    // that can store a grant pointing at a client that is not there.
    let grant = null;
    if (Array.isArray(req.body.clients)) {
      grant = await resolveClientGrant(req.body.clients);
      if (grant.unknown.length) {
        return res.status(400).json({ error: 'validation_error',
          error_description: `unknown client_id: ${grant.unknown.join(', ')}` });
      }
    }

    const allowed = ['username', 'name', 'email', 'hsm_url'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        // JSON null is how a client clears an optional field; Redis has no
        // null, and node-redis throws on it -- store the empty string.
        const v = req.body[key] === null ? '' : req.body[key];
        updates[key] = key === 'email' ? v.trim().toLowerCase() : v;
      }
    }

    if (grant) {
      updates.clients = JSON.stringify(grant.ids);
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

    // Same for email (already normalised in `updates`). A grandfathered record has
    // no email_index entry; claiming here simply starts indexing it going forward.
    if (updates.email) {
      const newEmail   = updates.email;
      const currentRaw = await redis.hGet(`user:${sub}`, 'email');

      if (currentRaw !== newEmail) {
        const claimed = await redis.hSetNX('email_index', newEmail, sub);
        if (!claimed) {
          const owner = await redis.hGet('email_index', newEmail);
          if (owner !== sub) {
            return res.status(409).json({ error: 'email_already_exists' });
          }
        }
        // Only release the old email if THIS sub owns its index entry. A
        // grandfathered old email may be indexed to a newer claimant of the same
        // address -- deleting that would free someone else's email.
        if (currentRaw && (await redis.hGet('email_index', currentRaw)) === sub) {
          await redis.hDel('email_index', currentRaw);
        }
        // The new address has not been proven -- any prior verification was for
        // the old one. Force re-verification.
        updates.email_verified = 'false';
      }
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

    const enrollment_url = `${issuer()}/enrollment#token=${token}`;

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
        // A claim value is a scalar. Objects/arrays/null would be stringified
        // ("[object Object]", "null") and served to RPs as such.
        if (!['string', 'number', 'boolean'].includes(typeof v)) {
          return res.status(400).json({ error: 'validation_error', error_description: `claim ${k} must be a string, number or boolean` });
        }
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
    const revokedTokens = await revokeUserTokens(sub);

    const [username, email, enrollToken] = await Promise.all([
      redis.hGet(`user:${sub}`, 'username'),
      redis.hGet(`user:${sub}`, 'email'),
      redis.hGet(`user:${sub}`, 'enrollment_token'),
    ]);
    // Release the email only if THIS sub owns its index entry (grandfathered
    // dupes may point elsewhere). Decide first, then delete everything in one MULTI.
    const ownsEmail = email && (await redis.hGet('email_index', email)) === sub;
    const tx = redis.multi().del(`user:${sub}`).sRem('users', sub);
    if (enrollToken) tx.del(`enrollment:${enrollToken}`);
    if (username)    tx.hDel('username_index', username);
    if (ownsEmail)   tx.hDel('email_index', email);
    await tx.exec();
    // The deleted user's key must leave /jwks.json now, not after the 60 s cache.
    invalidateJwksCache();

    await logSecurity(SEC.ADMIN_USER_DELETE, { sub, username, revokedTokens, ip: req.ip });
    console.log(`[Admin] User deleted: ${sub}`);
    res.status(204).send();
  } catch (err) { next(err); }
});

// --- GET /admin/audit-log -------------------------------------
export async function getAuditLog(req, res, next) {
  try {
    // Non-numeric input falls back to the default instead of feeding NaN to Redis (500).
    const toInt  = (v, def) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : def; };
    const limit  = Math.min(Math.max(toInt(req.query.limit, 20), 1), 500);
    const offset = Math.max(toInt(req.query.offset, 0), 0);

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

// (Re)send a confirm-your-email link to this user -- repeatable, generates a
// fresh token each time. Handler in emailVerify.js.
router.post('/:sub/send-verification-email', sendVerificationEmailHandler);

export default router;
