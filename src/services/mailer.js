/**
 * Outbound mail for enrollment links (EMAIL.MD).
 *
 * The application does NOT sign anything -- DKIM/SPF/DMARC live entirely on the
 * mail server. We only hand nodemailer to/from/subject/body over an authenticated
 * TLS connection. The feature is disabled (no-op) unless SMTP_HOST and MAIL_FROM
 * are set, so a deployment without SMTP keeps working (admin copies links by hand).
 *
 * Credentials come only from the environment -- never hard-coded, never logged.
 */
import nodemailer from 'nodemailer';

let transport = null;

export function isMailEnabled() {
  return Boolean(process.env.SMTP_HOST && process.env.MAIL_FROM);
}

function getTransport() {
  if (!transport && isMailEnabled()) {
    const mode = (process.env.SMTP_MODE ?? 'starttls').toLowerCase(); // 'ssl' | 'starttls'
    transport = nodemailer.createTransport({
      host:       process.env.SMTP_HOST,
      port:       Number(process.env.SMTP_PORT ?? (mode === 'ssl' ? 465 : 587)),
      secure:     mode === 'ssl',        // implicit TLS (465)
      requireTLS: mode === 'starttls',   // force STARTTLS upgrade -- no silent plaintext fallback
      auth:       process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,                     // no auth = IP-authorised relay
      // tls.rejectUnauthorized defaults to true -- bad certs are refused.
    });
  }
  return transport;
}

/**
 * Send an enrollment link. Returns { ok, error? } and NEVER throws -- a mail
 * failure must not break account creation; the admin always has copy-paste.
 *
 * The recipient is passed in by the caller from a trusted record (never from a
 * request body) -- the anti-open-relay rule lives at the call site.
 */
export async function sendEnrollmentEmail({ to, url, clientName, username }) {
  if (!isMailEnabled()) return { ok: false, error: 'mail_disabled' };
  try {
    const info = await getTransport().sendMail({
      from:    process.env.MAIL_FROM,
      to,
      subject: `Link your Encedo HSM${clientName ? ` — ${clientName}` : ''}`,
      text:
        `Hello${username ? ` ${username}` : ''},\n\n` +
        `Complete your secure sign-in setup by opening this link:\n${url}\n\n` +
        `The link expires in 24 hours. If you did not request this, ignore this message.\n`,
    });
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    console.error('[Mailer] send failed:', err.message);
    return { ok: false, error: err.message };
  }
}
