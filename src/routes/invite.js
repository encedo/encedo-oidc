import { randomBytes, randomUUID } from 'crypto';
import redis              from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validate, vEmail, vUsername, vDisplayName, vUrl, vKeyType } from '../middleware/validate.js';
import { resolveClientGrant } from '../services/clientGrant.js';

const DEFAULT_KEY_TYPE = 'Ed25519';

const issuer = () => process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;

// Invite tokens: randomBytes(32).toString('hex') = 64 hex chars
const TOKEN_RE = /^[a-f0-9]{64}$/;

/** Client id(s) from an invite record. Handles both the new clients[] shape and
 *  legacy single-client_id invites created before opt. A. */
const inviteClients = (data) =>
  Array.isArray(data.clients) ? data.clients : (data.client_id ? [data.client_id] : []);

// --- POST /admin/invite ---------------------------------------
export async function adminInviteHandler(req, res, next) {
  try {
    const { username, name, email, key_type } = req.body ?? {};
    // Multi-client invites (opt. A). Accept a legacy single client_id too, so an
    // older caller keeps working; the invitee's user is created with the whole list.
    const clients = Array.isArray(req.body?.clients)
      ? req.body.clients
      : (req.body?.client_id ? [req.body.client_id] : []);

    if (clients.length === 0) {
      return res.status(400).json({ error: 'validation_error', error_description: 'at least one client is required' });
    }

    // Identity is pinned here by the admin and enforced at /signup/register, so
    // username and email are REQUIRED — the invitee must not be able to choose a
    // foreign identity (account-takeover fix). name stays optional (display only).
    const checks = [
      vUsername(username),
      vEmail(email),
      vKeyType(key_type),
    ];
    if (name !== undefined) checks.push(vDisplayName(name));
    const err = checks.find(e => e) ?? null;
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    // Early uniqueness checks -- fail the invite now (surfaced to the admin)
    // instead of at signup (surfaced to the invitee, who can do nothing about it).
    // Not authoritative: signupRegisterHandler re-checks and claims both indexes
    // when the user is actually created.
    if (await redis.hGet('username_index', username.trim())) {
      return res.status(409).json({ error: 'username_already_exists' });
    }
    if (await redis.hGet('email_index', email.trim().toLowerCase())) {
      return res.status(409).json({ error: 'email_already_exists' });
    }

    // Every granted client must exist -- same rule as POST /admin/users.
    const grant = await resolveClientGrant(clients);
    if (grant.unknown.length) {
      return res.status(400).json({ error: 'validation_error',
        error_description: `unknown client_id: ${grant.unknown.join(', ')}` });
    }

    // Resolve names for display in the invites list (cheap, done once at creation).
    const namePipeline = redis.multi();
    for (const id of grant.ids) namePipeline.hGet(`client:${id}`, 'name');
    const names = await namePipeline.exec();
    const client_names = grant.ids.map((id, i) => names[i] || id);

    const token = randomBytes(32).toString('hex');
    // email_nonce proves the invite link was delivered to (and clicked from) the
    // pinned mailbox: completing signup+enrollment via this nonce sets
    // email_verified=true (EMAIL.MD). It travels only in the URL fragment (#...&n=),
    // which never reaches server logs, and it is NEVER returned to the admin --
    // otherwise the signal would lose its evidentiary value.
    //
    // NOTE: while UI email sending is not wired yet, the admin copies this link by
    // hand, so email_verified is not yet trustworthy end-to-end. Nothing consumes
    // it for access decisions until the connector enforcement (EMAIL.MD stage 4).
    const email_nonce = randomBytes(32).toString('base64url');
    await redis.set(`invite:${token}`, JSON.stringify({
      clients:      grant.ids,
      client_names,
      username:     username.trim(),
      name:         name?.trim() ?? '',
      email:        email.trim().toLowerCase(),
      key_type:     key_type ?? null, // null = user can choose during enrollment
      email_nonce,
    }), { EX: 86400 });

    const invite_url = `${issuer()}/signup#token=${token}&n=${email_nonce}`;
    await logSecurity(SEC.ADMIN_USER_CREATE, { action: 'invite_generated', clients: grant.ids, ip: req.ip });

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
    // signup.js shows a single label -- join names for a multi-client invite.
    const clientNames = data.client_names ?? (data.client_name ? [data.client_name] : []);
    res.json({
      client_name: clientNames.join(', '),
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
      // client invites carry `note`; user invites carry one or many clients.
      const clientNames = data.client_names
        ?? (data.client_name ? [data.client_name] : []);
      invites.push({
        token,
        type,
        client_id:   data.clients?.[0] ?? data.client_id ?? null, // first, for back-compat
        client_name: clientNames.join(', ') || data.note || '',
        username:    data.username ?? '',
        email:       data.email    ?? '',
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
    const { token, name, hsm_url, key_type: reqKeyType, n } = req.body ?? {};

    if (!token || !TOKEN_RE.test(token)) {
      return res.status(400).json({ error: 'invalid_token' });
    }

    // Validate user-supplied fields before consuming invite — so a validation
    // error doesn't burn the token. Identity (username/email) is NOT read from the
    // request body: it is pinned by the admin at invite time and enforced here,
    // so the invitee cannot self-assign a foreign identity (account-takeover fix).
    const err = validate(
      vDisplayName(name),
      vUrl(hsm_url, 'hsm_url', { httpsOnly: true, allowLocalhost: true }),
    );
    if (err) return res.status(400).json({ error: 'validation_error', error_description: err });

    // Peek invite (non-destructive) to read the admin-pinned identity, so a
    // username conflict can be reported without burning the token.
    const peek = await redis.get(`invite:${token}`);
    if (!peek) return res.status(404).json({ error: 'invite_not_found_or_expired' });
    const invitePeek = JSON.parse(peek);

    const uname = (invitePeek.username ?? '').trim();
    const email = (invitePeek.email ?? '').trim().toLowerCase();
    const idErr = validate(vUsername(uname), vEmail(email));
    if (idErr) {
      return res.status(400).json({ error: 'invite_incomplete',
        error_description: 'Invite must pin a valid username and email' });
    }

    if (await redis.hGet('email_index', email)) {
      return res.status(409).json({ error: 'email_already_exists' });
    }

    if (await redis.hGet('username_index', uname)) {
      return res.status(409).json({ error: 'username_already_exists' });
    }

    // Atomically consume invite — prevents race condition (two concurrent requests with same token)
    const raw = await redis.getDel(`invite:${token}`);
    if (!raw) return res.status(404).json({ error: 'invite_not_found_or_expired' });
    const invite = JSON.parse(raw);

    const inviteClientIds = inviteClients(invite);

    // Derive client redirect origin (first client) for the post-enrollment Close button
    const clientRaw = await redis.hGetAll(`client:${inviteClientIds[0]}`);
    const redirectUris = JSON.parse(clientRaw?.redirect_uris ?? '[]');
    let client_redirect_origin = null;
    if (redirectUris.length) {
      try { client_redirect_origin = new URL(redirectUris[0]).origin; } catch { /* ignore */ }
    }

    // Did the invitee arrive via the emailed link? The nonce is compared here, but
    // email_verified is only committed once enrollment actually completes (below,
    // via the enrollment session), so an abandoned signup never marks the mailbox
    // as verified.
    const via_email = Boolean(invite.email_nonce && n && n === invite.email_nonce);

    const sub = randomUUID();
    const record = {
      sub,
      username:   uname,
      name:       (name ?? '').trim(),
      email,      // pinned by the invite, already normalised above
      hsm_url:    hsm_url.trim(),
      clients:    JSON.stringify(inviteClientIds),
      email_verified: 'false',   // set to 'true' by /enrollment/submit if via_email
      created_at: new Date().toISOString(),
    };

    await redis.hSet(`user:${sub}`, record);
    await redis.sAdd('users', sub);
    await redis.hSet('username_index', uname, sub);
    await redis.hSet('email_index', email, sub);

    // key_type priority: invite-forced > user-choice > default
    const forcedKeyType = invite.key_type ?? reqKeyType ?? DEFAULT_KEY_TYPE;

    const enrollToken = randomBytes(32).toString('base64url');
    await redis.set(`enrollment:${enrollToken}`, JSON.stringify({
      sub,
      username:          uname,
      hsm_url:           hsm_url.trim(),
      forced_key_type:   forcedKeyType,
      client_redirect_origin,
      via_email,   // enrollment/submit reads this to set user.email_verified
    }), { EX: 3600 }); // 1h — user is actively enrolling right now
    await redis.hSet(`user:${sub}`, { enrollment_token: enrollToken });

    await logSecurity(SEC.ADMIN_USER_CREATE, { action: 'signup', sub, username: uname, clients: inviteClientIds, ip: req.ip });

    res.status(201).json({
      sub,
      enrollment_token: enrollToken,
      client_redirect_origin,
    });
  } catch (err) { next(err); }
}
