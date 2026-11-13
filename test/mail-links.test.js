// Links the admin emails from the panel: the enrollment link of an existing user
// (Add user / Renew) and the re-attestation link. A fake SMTP server in this
// process takes the mail; SMTP_MODE=plain (no TLS) only for this test.
//
// Checks: the mail goes to the address on the record, the emailed enrollment link
// carries an email nonce that the admin never sees, and completing enrollment from
// that link sets email_verified. Spawns its own redis-server + app; skips without Redis.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';

const REDIS_PORT = 6396;
const APP_PORT   = 3396;
const BASE       = `http://127.0.0.1:${APP_PORT}`;
const SECRET     = 'test-secret';

let hasRedis = true;
try { execSync('command -v redis-server', { stdio: 'ignore' }); } catch { hasRedis = false; }
const opt = hasRedis ? {} : { skip: 'redis-server not installed' };

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const H = { Authorization: `Bearer ${SECRET}`, 'Content-Type': 'application/json' };
const call = (method, p, b) => fetch(BASE + p, { method, headers: H, body: b && JSON.stringify(b) })
  .then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));

// --- a minimal SMTP server: enough for nodemailer, keeps every message ----------
const mails = [];
let smtp;
function startSmtp() {
  smtp = net.createServer((sock) => {
    let buf = '', inData = false, cur = { rcpt: [], data: '' };
    const say = (l) => sock.write(l + '\r\n');
    say('220 fake ESMTP');
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (inData) {
          if (line === '.') { inData = false; mails.push(cur); cur = { rcpt: [], data: '' }; say('250 queued'); }
          else cur.data += (line.startsWith('..') ? line.slice(1) : line) + '\n';
          continue;
        }
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') say('250 fake');
        else if (cmd === 'MAIL') say('250 ok');
        else if (cmd === 'RCPT') { cur.rcpt.push(line.match(/<([^>]+)>/)?.[1]); say('250 ok'); }
        else if (cmd === 'DATA') { inData = true; say('354 go'); }
        else if (cmd === 'QUIT') { say('221 bye'); sock.end(); }
        else say('250 ok');
      }
    });
  });
  return new Promise(r => smtp.listen(0, '127.0.0.1', () => r(smtp.address().port)));
}
// The link as the mail carries it (quoted-printable soft breaks undone).
const linkIn = (mail, path) => {
  const text = mail.data.replace(/=\r?\n/g, '').replace(/=3D/g, '=');
  return text.match(new RegExp(`https?://[^\\s"<>]+/${path}#token=[A-Za-z0-9_&=-]+`))?.[0] ?? null;
};

let redisProc, appProc;
before(async () => {
  if (!hasRedis) return;
  const smtpPort = await startSmtp();
  redisProc = spawn('redis-server', ['--port', String(REDIS_PORT), '--dir', mkdtempSync(join(tmpdir(), 'oidc-mail-')), '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
  for (let i = 0; i < 50; i++) { const up = await new Promise(res => { const s = net.connect(REDIS_PORT, '127.0.0.1'); s.on('connect', () => { s.destroy(); res(true); }); s.on('error', () => res(false)); }); if (up) break; await sleep(100); }
  appProc = spawn('node', ['src/app.js'], {
    stdio: 'ignore',
    env: { ...process.env, REDIS_URL: `redis://127.0.0.1:${REDIS_PORT}`, PORT: String(APP_PORT), ISSUER: BASE,
      ADMIN_SECRET: SECRET, ADMIN_ALLOWED_IPS: '127.0.0.1,::1',
      SMTP_HOST: '127.0.0.1', SMTP_PORT: String(smtpPort), SMTP_MODE: 'plain', MAIL_FROM: 'OIDC test <oidc@test.example>' },
  });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/health')).ok) break; } catch {} await sleep(100); }
});
after(() => { try { appProc?.kill(); } catch {} try { redisProc?.kill(); } catch {} smtp?.close(); });

function edKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  return { pubHex: raw.toString('hex'), kid: crypto.createHash('sha1').update(raw).digest('hex').slice(0, 32),
    sign: (m) => crypto.sign(null, Buffer.from(m), privateKey).toString('base64url') };
}

test('enrollment link by email: sent to the record, nonce never returned, enrollment from it verifies the email', opt, async () => {
  const u = (await call('POST', '/admin/users', { username: 'mailer1', name: 'Mail Test', email: 'mail1@example.test', hsm_url: 'https://sw.ence.do' })).body;
  assert.ok(u.sub);
  const before = mails.length;
  const r = await call('POST', `/admin/users/${u.sub}/enrollment/send-email`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body, { ok: true, to: 'mail1@example.test' }, 'no nonce, no url for the admin');
  assert.equal(mails.length, before + 1);
  const mail = mails.at(-1);
  assert.deepEqual(mail.rcpt, ['mail1@example.test']);
  const link = linkIn(mail, 'enrollment');
  assert.ok(link, 'the mail carries the enrollment link');
  const frag = new URLSearchParams(link.split('#')[1]);
  assert.equal(frag.get('token'), u.enrollment_url.split('#token=')[1], 'the same link the admin holds');
  assert.ok(frag.get('n'), 'plus an email nonce');

  // A second send keeps the nonce (the first mail stays valid).
  await call('POST', `/admin/users/${u.sub}/enrollment/send-email`);
  assert.equal(new URLSearchParams(linkIn(mails.at(-1), 'enrollment').split('#')[1]).get('n'), frag.get('n'));

  // Enrollment from the emailed link -> email_verified.
  const k = edKey();
  const v = await call('POST', '/enrollment/validate', { token: frag.get('token') });
  const s = await call('POST', '/enrollment/submit', { token: frag.get('token'), hsm_url: 'https://sw.ence.do', kid: k.kid,
    pubkey: k.pubHex, key_type: 'Ed25519', signature: k.sign(v.body.challenge), n: frag.get('n') });
  assert.equal(s.status, 200, JSON.stringify(s.body));
  const rec = (await call('GET', `/admin/users/${u.sub}`)).body;
  assert.equal(String(rec.email_verified), 'true');

  // The link is used up: nothing left to email.
  const again = await call('POST', `/admin/users/${u.sub}/enrollment/send-email`);
  assert.equal(again.status, 409); assert.equal(again.body.error, 'no_link');
});

test('a hand-copied enrollment link (no nonce) does not verify the email', opt, async () => {
  const u = (await call('POST', '/admin/users', { username: 'mailer2', name: 'Mail Two', email: 'mail2@example.test', hsm_url: 'https://sw.ence.do' })).body;
  const token = u.enrollment_url.split('#token=')[1];
  const k = edKey();
  const v = await call('POST', '/enrollment/validate', { token });
  assert.equal((await call('POST', '/enrollment/submit', { token, hsm_url: 'https://sw.ence.do', kid: k.kid,
    pubkey: k.pubHex, key_type: 'Ed25519', signature: k.sign(v.body.challenge) })).status, 200);
  assert.equal(String((await call('GET', `/admin/users/${u.sub}`)).body.email_verified), 'false');

  // ... and the re-attestation link goes out by email too.
  const link = await call('POST', `/admin/users/${u.sub}/reattest`);
  assert.equal(link.status, 200);
  const m = await call('POST', `/admin/users/${u.sub}/reattest/send-email`);
  assert.equal(m.status, 200, JSON.stringify(m.body));
  assert.deepEqual(mails.at(-1).rcpt, ['mail2@example.test']);
  assert.equal(linkIn(mails.at(-1), 'reattest'), link.body.reattest_url);
});
