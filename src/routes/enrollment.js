import { Router }                                  from 'express';
import { createHash, createPublicKey, verify,
         randomBytes }                             from 'crypto';
import redis from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { validateAttestation } from '../services/attestation.js';
import { invalidateJwksCache } from './oidc.js';
import { rateLimit } from '../middleware/rateLimit.js';

const router = Router();

// --- Helpers --------------------------------------------------

/**
 * kid = first 16 bytes of SHA-1(raw pubkey bytes) -- matches Encedo HSM convention.
 * HSM truncates SHA-1 to 16 bytes (32 hex chars), not the full 20 bytes (40 hex chars).
 */
function deriveKid(pubkeyHex) {
  return createHash('sha1')
    .update(Buffer.from(pubkeyHex, 'hex'))
    .digest('hex')
    .slice(0, 32);
}

/**
 * Verify Ed25519 signature (same logic as oidc.js).
 * pubkeyHex = 64 hex chars (32-byte raw key).
 * msg       = string that was signed (the challenge).
 * sigB64url = base64url signature from HSM (converted from standard base64).
 */
function verifyEnrollmentSig(pubkeyHex, msg, sigB64url) {
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const pubkeyDer  = Buffer.concat([spkiPrefix, Buffer.from(pubkeyHex, 'hex')]);
  const publicKey  = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
  const sigBuf     = Buffer.from(sigB64url, 'base64url');
  return verify(null, Buffer.from(msg), publicKey, sigBuf);
}

// --- GET /enrollment/validate?token= --------------------------
// Returns user info + challenge for key-possession proof.
// Calling validate activates the session: TTL shortened to 30 min,
// challenge generated (idempotent on repeated calls).
router.get('/validate',
  rateLimit({ prefix: 'enroll-validate', max: 10, window: 60,
    keyFn: req => req.query.token ?? req.ip }),
  async (req, res, next) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'missing_token' });

    const raw = await redis.get(`enrollment:${token}`);
    if (!raw) return res.status(404).json({ error: 'invalid_or_expired_token' });

    const session = JSON.parse(raw);

    // Generate challenge once and shorten TTL -- only on first call (idempotent).
    // Subsequent calls return the same challenge WITHOUT resetting TTL,
    // preventing an attacker from indefinitely extending the session window.
    if (!session.challenge) {
      session.challenge = randomBytes(32).toString('base64url');
      await redis.set(`enrollment:${token}`, JSON.stringify(session), { EX: 1800 });
    }

    const userRaw = await redis.hGetAll(`user:${session.sub}`);
    res.json({
      sub:       session.sub,
      username:  session.username,
      hsm_url:   userRaw?.hsm_url ?? '',
      challenge: session.challenge,
    });
  } catch (err) { next(err); }
});

// --- POST /enrollment/submit -----------------------------------
// Body: { token, hsm_url, kid, pubkey, signature }
// signature = Ed25519 sign(challenge) with the new key, base64url-encoded.
router.post('/submit',
  rateLimit({ prefix: 'enroll-submit', max: 5, window: 60,
    keyFn: req => req.body?.token ?? req.ip }),
  async (req, res, next) => {
  try {
    const { token, hsm_url, kid, pubkey, signature, genuine, crt } = req.body;

    if (!token)     return res.status(400).json({ error: 'missing_token' });
    if (!hsm_url)   return res.status(400).json({ error: 'missing_hsm_url' });
    if (!kid)       return res.status(400).json({ error: 'missing_kid' });
    if (!pubkey)    return res.status(400).json({ error: 'missing_pubkey' });
    if (!signature) return res.status(400).json({ error: 'missing_signature',
      error_description: 'Enrollment requires a key-possession proof (sign the challenge)' });

    // Validate token format: randomBytes(32).toString('base64url') = 43 chars
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
      return res.status(400).json({ error: 'invalid_token_format' });
    }

    // Validate pubkey: exactly 64 hex chars (32-byte raw Ed25519)
    if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) {
      return res.status(400).json({ error: 'invalid_pubkey',
        error_description: 'pubkey must be 64 hex characters (32-byte Ed25519 raw key)' });
    }

    // Validate kid = SHA-1(pubkey) -- matches HSM convention, server-derived
    const expectedKid = deriveKid(pubkey.trim().toLowerCase());
    if (typeof kid !== 'string' || kid.trim().toLowerCase() !== expectedKid) {
      return res.status(400).json({ error: 'invalid_kid',
        error_description: 'kid must equal SHA-1(pubkey)' });
    }

    // Consume token (one-time use) -- also retrieves the challenge
    const raw = await redis.getDel(`enrollment:${token}`);
    if (!raw) {
      await logSecurity(SEC.ENROLL_FAIL, { reason: 'invalid_token', ip: req.ip });
      return res.status(404).json({ error: 'invalid_or_expired_token' });
    }

    const session = JSON.parse(raw);

    if (!session.challenge) {
      // validate was never called -- no challenge issued, cannot verify possession
      await logSecurity(SEC.ENROLL_FAIL, { reason: 'no_challenge', sub: session.sub, ip: req.ip });
      return res.status(400).json({ error: 'invalid_request',
        error_description: 'Call /enrollment/validate first to receive a challenge' });
    }

    const { sub, username, challenge } = session;

    // -- Concurrency lock -- one active enrollment per user ----------
    const lockKey = `enroll_lock:${sub}`;
    const locked  = await redis.set(lockKey, '1', { NX: true, EX: 30 });
    if (!locked) {
      return res.status(409).json({ error: 'enrollment_in_progress',
        error_description: 'Another enrollment is already in progress for this account' });
    }

    // -- Key-possession proof + enrollment (under lock) ------------
    try {
      let sigValid = false;
      try {
        sigValid = verifyEnrollmentSig(
          pubkey.trim().toLowerCase(),
          challenge,
          signature,
        );
      } catch {
        sigValid = false;
      }

      if (!sigValid) {
        await logSecurity(SEC.ENROLL_FAIL, { reason: 'invalid_signature', sub, ip: req.ip });
        return res.status(400).json({ error: 'invalid_enrollment_signature',
          error_description: 'Signature over challenge does not match the submitted public key' });
      }

      const exists = await redis.sIsMember('users', sub);
      if (!exists) {
        await logSecurity(SEC.ENROLL_FAIL, { reason: 'user_not_found', sub, ip: req.ip });
        return res.status(404).json({ error: 'user_not_found' });
      }

      // Hygiene: one keypair per user (not a security boundary -- enrollment_token is the gate)
      const subs     = await redis.sMembers('users');
      const pipeline = redis.multi();
      for (const s of subs) pipeline.hGet(`user:${s}`, 'pubkey');
      const existingPubkeys = await pipeline.exec();
      if (existingPubkeys.some(p => p === pubkey.trim().toLowerCase())) {
        await logSecurity(SEC.ENROLL_FAIL, { reason: 'duplicate_pubkey', sub, ip: req.ip });
        return res.status(409).json({ error: 'pubkey_already_registered',
          error_description: 'This public key is already enrolled for another user' });
      }

      // -- HSM attestation -----------------------------------------
      const attestResult = await validateAttestation(genuine, crt);
      const { hw_attested } = attestResult;
      if (hw_attested !== 'true') {
        console.warn(`[Enrollment] Attestation not verified: hw_attested=${hw_attested} reason=${attestResult.reason ?? '-'}`);
      }

      const userFields = {
        hsm_url:      hsm_url.trim(),
        kid:          expectedKid,
        pubkey:       pubkey.trim().toLowerCase(),
        hw_attested,
        enrolled_at:  new Date().toISOString(),
        updated_at:   new Date().toISOString(),
      };
      if (attestResult.crt) userFields.hsm_crt = attestResult.crt;

      await redis.hSet(`user:${sub}`, userFields);
      await redis.hDel(`user:${sub}`, 'enrollment_token');

      // Revoke all active access tokens -- old key is no longer valid
      const tokenKeys = await redis.sMembers(`user_tokens:${sub}`);
      if (tokenKeys.length > 0) {
        const pipeline = redis.multi();
        for (const k of tokenKeys) pipeline.del(k);
        pipeline.del(`user_tokens:${sub}`);
        await pipeline.exec();
      }

      await logSecurity(SEC.ENROLL_OK, { sub, username, kid: expectedKid, hw_attested, ip: req.ip });
      console.log(`[Enrollment] Enrolled kid=${expectedKid} hw_attested=${hw_attested}`);
      invalidateJwksCache();

      res.json({ ok: true, sub, username, kid: expectedKid, hw_attested });
    } finally {
      await redis.del(lockKey);
    }
  } catch (err) { next(err); }
});

export default router;
