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

const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/**
 * HTML body in the same palette as the web UI (signup.html): brand purple
 * #6E358C, navy #2A225E, text #222, muted #666, page #f4f4f4, card #fff.
 * Table-based + inline styles for email-client compatibility.
 */
function renderHtml({ heading, greetingName, intro, url, buttonLabel }) {
  const u = esc(url);
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f4f4f4;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:20px;font-family:'Inter',Arial,Helvetica,sans-serif;">
<tr><td style="padding:34px 40px 6px;text-align:center;">
<span style="font-size:22px;font-weight:700;letter-spacing:.02em;color:#6E358C;">encedo</span></td></tr>
<tr><td style="padding:16px 40px 32px;">
<h1 style="margin:0 0 14px;font-size:20px;font-weight:700;color:#2A225E;">${esc(heading)}</h1>
<p style="margin:0 0 10px;font-size:15px;line-height:1.6;color:#222;">Hello${greetingName ? ' ' + esc(greetingName) : ''},</p>
<p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#444;">${esc(intro)}</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px;"><tr>
<td style="border-radius:22px;background:#6E358C;"><a href="${u}" style="display:inline-block;padding:13px 30px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:22px;">${esc(buttonLabel)}</a></td>
</tr></table>
<p style="margin:0 0 6px;font-size:12px;line-height:1.6;color:#666;">Or paste this link into your browser:</p>
<p style="margin:0 0 20px;font-size:12px;line-height:1.5;word-break:break-all;"><a href="${u}" style="color:#6E358C;">${u}</a></p>
<p style="margin:0;font-size:12px;line-height:1.6;color:#999;">This link expires in 24 hours. If you did not request this, you can ignore this message.</p>
</td></tr></table></td></tr></table></body></html>`;
}

/**
 * Send an enrollment link. Returns { ok, error? } and NEVER throws -- a mail
 * failure must not break account creation; the admin always has copy-paste.
 *
 * The recipient is passed in by the caller from a trusted record (never from a
 * request body) -- the anti-open-relay rule lives at the call site. `name` is the
 * display greeting (caller passes the full name, falling back to the username).
 */
export async function sendEnrollmentEmail({ to, url, clientName, name }) {
  if (!isMailEnabled()) return { ok: false, error: 'mail_disabled' };
  const intro = 'Complete your secure sign-in setup by opening the link below.';
  try {
    const info = await getTransport().sendMail({
      from:    process.env.MAIL_FROM,
      to,
      subject: `Link your Encedo HSM${clientName ? ` — ${clientName}` : ''}`,
      text:
        `Hello${name ? ` ${name}` : ''},\n\n${intro}\n${url}\n\n` +
        `The link expires in 24 hours. If you did not request this, ignore this message.\n`,
      html: renderHtml({ heading: 'Link your Encedo HSM', greetingName: name, intro, url, buttonLabel: 'Complete setup' }),
    });
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    console.error('[Mailer] send failed:', err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * Send a standalone "confirm your email address" link -- independent of
 * enrollment, so it works for any user (on-site Add, copied invite link, or a
 * changed address). Clicking it sets email_verified. Never throws.
 */
export async function sendVerificationEmail({ to, url, name }) {
  if (!isMailEnabled()) return { ok: false, error: 'mail_disabled' };
  const intro = 'Confirm this is your email address by opening the link below.';
  try {
    const info = await getTransport().sendMail({
      from:    process.env.MAIL_FROM,
      to,
      subject: 'Confirm your email address',
      text:
        `Hello${name ? ` ${name}` : ''},\n\n${intro}\n${url}\n\n` +
        `The link expires in 24 hours. If you did not request this, ignore this message.\n`,
      html: renderHtml({ heading: 'Confirm your email address', greetingName: name, intro, url, buttonLabel: 'Confirm email' }),
    });
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    console.error('[Mailer] send failed:', err.message);
    return { ok: false, error: err.message };
  }
}
