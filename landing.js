/* Landing page — rail facts from /health, and the signing demonstration.
   Kept in an external file because CSP is `script-src 'self'` (see src/app.js). */

/* ---- rail: the issuer and build this instance actually reports ------------
   Same source as the status page (index.js). On failure the markup's static
   values stay — a landing page that renders an error is worse than one that
   shows the canonical issuer. */
(async function () {
  try {
    const r = await fetch('/health');
    const h = await r.json();
    if (h.issuer) document.getElementById('rail-issuer').textContent = h.issuer;
    const ver = h.version && h.version !== 'unknown' ? 'v' + h.version : '';
    const build = h.commit && h.commit !== 'unknown' ? h.commit : '';
    if (ver || build) document.getElementById('rail-ver').textContent = [ver, build].filter(Boolean).join(' · ');
  } catch { /* offline or opened from disk — keep the static values */ }
})();

/* ---- the demonstration ---------------------------------------------------
 * The claim on this page is that the server cannot sign for you, and that is
 * exactly the kind of claim a landing page can *show*. So the signature below
 * is real: this page generates a throwaway Ed25519 pair, signs the very
 * signing_input it prints, and verifies it — with WebCrypto, the same primitive
 * the provider uses. Both halves of the key are created here and thrown away;
 * they protect nothing.
 *
 * Ed25519 in WebCrypto needs Chrome 105+ / Firefox 113+ (the same floor as
 * enrollment.html). Where it is missing the row still fills — with random bytes,
 * and without the word "valid", because nothing was verified.
 */
(function () {
  const inputEl  = document.getElementById('w-input');
  const sigEl    = document.getElementById('w-sig');
  const verifyEl = document.getElementById('w-verify');
  const voidEl   = document.getElementById('w-void');
  const replay   = document.getElementById('replay');
  const still    = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const b64url = (bytes) => btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64urlStr = (s) => b64url(new TextEncoder().encode(s));

  // The shape the backend really builds: base64url(header) + '.' + base64url(payload).
  // kid is SHA-1 of the public key, truncated to 16 bytes -- 32 hex chars, as the provider derives it.
  const HEADER = { alg: 'EdDSA', kid: 'a4f1c0e27b3d9e51c8f2a06d4b19e37c', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const PAYLOAD = {
    iss: 'https://oidc.encedo.com',
    sub: '9f2c1d84-7b3e-4a16-9c05-2e8ab6d4f107',
    aud: 'carbonio',
    exp: now + 3600, iat: now,
    auth_time: now, amr: ['hwk'],
    preferred_username: 'operator', email_verified: true,
  };
  const SIGNING_INPUT = b64urlStr(JSON.stringify(HEADER)) + '.' + b64urlStr(JSON.stringify(PAYLOAD));

  let signature = null;   // filled by sign(), or by random bytes on fallback
  let verified = false;
  let timers = [];
  const at = (fn, ms) => timers.push(setTimeout(fn, ms));

  async function sign() {
    try {
      const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const msg = new TextEncoder().encode(SIGNING_INPUT);
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, msg));
      verified = await crypto.subtle.verify({ name: 'Ed25519' }, pair.publicKey, sig, msg);
      signature = b64url(sig);
    } catch {
      const bytes = crypto.getRandomValues(new Uint8Array(64));   // 64 B — the size of an Ed25519 signature
      signature = b64url(bytes);
      verified = false;
    }
  }

  const churn = () => b64url(crypto.getRandomValues(new Uint8Array(64)));
  const verifyText = () => verified
    ? 'crypto.verify(EdDSA, pubkey) → valid'
    : 'crypto.verify(EdDSA, pubkey)';

  function finish() {
    inputEl.textContent = SIGNING_INPUT;
    sigEl.textContent = signature;
    verifyEl.textContent = verifyText();
    voidEl.textContent = '— nothing —';
  }

  function run() {
    timers.forEach(clearTimeout); timers = [];
    if (still) { finish(); return }

    sigEl.textContent = ''; verifyEl.textContent = ''; voidEl.textContent = '';
    inputEl.innerHTML = '<span class="caret">&nbsp;</span>';

    // Built, then signed, then verified, then nothing: the four states this flow
    // actually has. The signature churns a few times before it settles, so it
    // reads as *output* rather than as a second string someone typed in.
    let i = 0;
    function type() {
      if (i > SIGNING_INPUT.length) { at(seal, 380); return }
      inputEl.innerHTML = SIGNING_INPUT.slice(0, i) + '<span class="caret">&nbsp;</span>';
      i += 6;
      at(type, 18);
    }
    function seal() {
      inputEl.textContent = SIGNING_INPUT;
      let n = 0;
      (function spin() {
        sigEl.textContent = (++n < 7) ? churn() : signature;
        at(n < 7 ? spin : confirm, n < 7 ? 55 : 420);
      })();
    }
    function confirm() {
      verifyEl.textContent = verifyText();
      at(() => { voidEl.textContent = '— nothing —' }, 650);
    }
    type();
  }

  replay.addEventListener('click', run);
  sign().then(run);
})();
