/**
 * Standalone email verification -- independent of enrollment.
 *
 * email_verified only becomes true when the user clicks a link that the server
 * emailed to the address on their record. This works for anyone: an on-site
 * (Add) account, a user who got a copied invite link, or someone who just
 * changed their address. The enrollment/invite nonce path (EMAIL.MD) still
 * auto-verifies invitees who complete via the emailed invite link; this is the
 * general-purpose path the admin can trigger from Edit User at any time.
 */
import { randomBytes } from 'crypto';
import redis from '../services/redis.js';
import { logSecurity, SEC } from '../services/securityLog.js';
import { sendVerificationEmail, isMailEnabled } from '../services/mailer.js';

const issuer = () => process.env.ISSUER ?? `http://localhost:${process.env.PORT ?? 3000}`;
const TOKEN_RE = /^[a-f0-9]{64}$/;

// --- POST /admin/users/:sub/send-verification-email -----------
// Emails a confirm-your-address link to the address on the user record (never
// one from the request body). The token is stored server-side; the response
// carries no token/url.
export async function sendVerificationEmailHandler(req, res, next) {
  try {
    if (!isMailEnabled()) {
      return res.status(503).json({ error: 'mail_disabled', error_description: 'SMTP is not configured' });
    }
    const { sub } = req.params;
    const user = await redis.hGetAll(`user:${sub}`);
    if (!user?.sub) return res.status(404).json({ error: 'user_not_found' });

    const to = (user.email ?? '').trim().toLowerCase();
    if (!to) return res.status(400).json({ error: 'user_has_no_email' });

    const token = randomBytes(32).toString('hex');
    // Bind the token to BOTH sub and the exact address, so a later email change
    // cannot be verified by an old link (checked again at confirm time).
    await redis.set(`email_verify:${token}`, JSON.stringify({ sub, email: to }), { EX: 86400 });
    const url = `${issuer()}/verify-email#token=${token}`;

    const result = await sendVerificationEmail({ to, url, username: user.username });
    if (!result.ok) {
      await logSecurity(SEC.ENROLL_FAIL, { action: 'verify_email_failed', reason: result.error, ip: req.ip });
      return res.status(502).json({ error: 'mail_send_failed', error_description: result.error });
    }

    await logSecurity(SEC.EMAIL_VERIFY_SENT, { sub, to, ip: req.ip });
    res.json({ sent: true, to });
  } catch (err) { next(err); }
}

// --- POST /verify-email/confirm  (PUBLIC) ---------------------
// The token is the credential -- no admin auth. Rate-limited at the route.
export async function confirmEmailHandler(req, res, next) {
  try {
    const { token } = req.body ?? {};
    if (!token || !TOKEN_RE.test(token)) return res.status(400).json({ error: 'invalid_token' });

    const raw = await redis.getDel(`email_verify:${token}`);   // one-time use
    if (!raw) return res.status(404).json({ error: 'invalid_or_expired_token' });
    const { sub, email } = JSON.parse(raw);

    const user = await redis.hGetAll(`user:${sub}`);
    if (!user?.sub) return res.status(404).json({ error: 'user_not_found' });

    // Must still be the address the link was issued for -- otherwise a stale link
    // would verify an address the user has since changed away from.
    if ((user.email ?? '').trim().toLowerCase() !== email) {
      return res.status(409).json({ error: 'email_changed',
        error_description: 'This address is no longer on the account. Request a new link.' });
    }

    await redis.hSet(`user:${sub}`, { email_verified: 'true', updated_at: new Date().toISOString() });
    await logSecurity(SEC.EMAIL_VERIFIED, { sub, email, ip: req.ip });
    res.json({ ok: true, email });
  } catch (err) { next(err); }
}
