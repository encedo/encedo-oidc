/**
 * Re-attestation of an enrolled key (HEM firmware 1.3) -- the user's existing
 * key, not a new one: the same kid stays in the JWKS, nothing changes for the
 * relying parties. The admin issues a one-time link (POST /admin/users/:sub/reattest);
 * the user opens /reattest, authorizes on the HEM, and the page sends
 * hem.attest() for the enrolled kid over a fresh server challenge.
 *
 * The attestation carries its own proof of possession (the key signs
 * aud || pubkey || nonce), so no separate challenge signature is needed.
 * A failed check keeps the link (retry with the right device); a verified or
 * token_only result replaces the record's attestation fields and consumes it.
 * The policy is not applied: this records evidence, it never removes a key.
 */
import { Router } from 'express';
import redis, { casSet, casDel } from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { verifyKeyAttestation, newAttestChallenge } from '../services/attestation.js';
import { rateLimit } from '../middleware/rateLimit.js';

const router = Router();
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const REATTEST_TTL = 86400;   // the link; the first open shortens it to 30 min (as enrollment)

/**
 * The stored public key in the form the HEM attests it: Ed25519 raw 32 B as
 * stored; EC stored as uncompressed X||Y, attested as the compressed point.
 * Decided by length, so a record from before key_type existed works too.
 */
export function hemPubkeyHex(stored) {
  const hex = String(stored ?? '').toLowerCase();
  if (hex.length === 64) return hex;                               // Ed25519
  const b = Buffer.from(hex, 'hex');
  if (![64, 96, 132].includes(b.length)) return null;              // P-256 / P-384 / P-521
  const x = b.subarray(0, b.length / 2), y = b.subarray(b.length / 2);
  return ((y[y.length - 1] & 1) ? '03' : '02') + x.toString('hex');
}

async function readSession(token) {
  if (!TOKEN_RE.test(token)) return { error: [400, 'invalid_token_format'] };
  const raw = await redis.get(`reattest:${token}`);
  if (!raw) return { error: [404, 'invalid_or_expired_token'] };
  const session = JSON.parse(raw);
  const user = await redis.hGetAll(`user:${session.sub}`);
  if (!user?.sub) return { error: [404, 'user_not_found'] };
  // The link names the key it was issued for: a re-enrollment since then voids it.
  if (!user.kid || user.kid !== session.kid) return { error: [409, 'key_changed'] };
  return { raw, session, user };
}

const tokenOf = (req) => (typeof req.body?.token === 'string' ? req.body.token : '');

// --- POST /reattest/validate  { token } ------------------------------------------
router.post('/validate',
  rateLimit({ prefix: 'reattest-validate-ip', max: 30, window: 60 }),
  rateLimit({ prefix: 'reattest-validate', max: 10, window: 60, keyFn: req => tokenOf(req) || req.ip }),
  async (req, res, next) => {
  try {
    const token = tokenOf(req);
    if (!token) return res.status(400).json({ error: 'missing_token' });
    let { raw, session, user, error } = await readSession(token);
    if (error) return res.status(error[0]).json({ error: error[1] });

    // One challenge per link, created on the first open (compare-and-set, as enrollment).
    if (!session.attest) {
      session.attest = newAttestChallenge();
      const won = await casSet(`reattest:${token}`, raw, JSON.stringify(session), 1800);
      if (!won) {
        const again = await redis.get(`reattest:${token}`);
        if (!again) return res.status(404).json({ error: 'invalid_or_expired_token' });
        session = JSON.parse(again);
      }
    }
    res.json({
      sub: user.sub, username: user.username, hsm_url: user.hsm_url ?? '',
      kid: user.kid, key_type: user.key_type || 'Ed25519', attest: session.attest,
    });
  } catch (err) { next(err); }
});

// --- POST /reattest/submit  { token, attestation, crt? } -------------------------
router.post('/submit',
  rateLimit({ prefix: 'reattest-submit-ip', max: 20, window: 60 }),
  rateLimit({ prefix: 'reattest-submit', max: 5, window: 60, keyFn: req => tokenOf(req) || req.ip }),
  async (req, res, next) => {
  try {
    const token = tokenOf(req);
    if (!token) return res.status(400).json({ error: 'missing_token' });
    const { attestation, crt } = req.body ?? {};
    const { raw, session, user, error } = await readSession(token);
    if (error) return res.status(error[0]).json({ error: error[1] });
    if (!session.attest) return res.status(400).json({ error: 'invalid_request',
      error_description: 'Call /reattest/validate first to receive a challenge' });

    const sub = user.sub;
    // Same lock as enrollment: the key must not change while it is being attested.
    const lockKey = `enroll_lock:${sub}`;
    if (!(await redis.set(lockKey, '1', { NX: true, EX: 30 }))) {
      return res.status(409).json({ error: 'enrollment_in_progress' });
    }
    try {
      const pubkeyHex = hemPubkeyHex(user.pubkey);
      if (!pubkeyHex) return res.status(409).json({ error: 'no_key' });
      const attest = await verifyKeyAttestation({
        attestation: attestation ?? null, crt: crt ?? null,
        challenge: session.attest, kid: user.kid, pubkeyHex,
      });
      console.log(`[Reattest] sub=${sub} kid=${user.kid} status=${attest.status} assurance=${attest.assurance ?? '-'} online=${attest.online ?? '-'} reason=${attest.reason ?? '-'}`);

      if (attest.status === 'failed' || attest.status === 'absent') {
        await logSecurity(SEC.REATTEST_FAIL, { sub, kid: user.kid, attest_status: attest.status, attest_reason: attest.reason, ip: req.ip });
        return res.status(400).json({ error: 'attestation_failed',
          error_description: `The key attestation did not pass (${attest.status}${attest.reason ? ': ' + attest.reason : ''}). The link stays valid -- try again with the module that holds this key.` });
      }

      if (!(await casDel(`reattest:${token}`, raw))) {
        return res.status(409).json({ error: 'invalid_or_expired_token',
          error_description: 'This link was used or replaced in the meantime' });
      }
      const now = new Date().toISOString();
      await redis.hSet(`user:${sub}`, {
        hw_attested:      attest.status === 'verified' ? 'true' : 'false',
        attest_status:    attest.status,
        attest_assurance: attest.assurance ?? '',
        attest_reason:    attest.reason ?? '',
        attest_online:    attest.online ?? '',
        attest_jwt:       attest.jwt ?? '',
        attest_at:        now,
        hsm_crt:          attest.crt ?? '',
        updated_at:       now,
      });
      await redis.hDel(`user:${sub}`, 'reattest_token');
      await logSecurity(SEC.REATTEST_OK, { sub, username: user.username, kid: user.kid,
        attest_status: attest.status, attest_assurance: attest.assurance, ip: req.ip });
      res.json({ ok: true, username: user.username, kid: user.kid,
        attest_status: attest.status, attest_assurance: attest.assurance });
    } finally {
      await redis.del(lockKey);
    }
  } catch (err) { next(err); }
});

export default router;
