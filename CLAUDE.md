# Encedo OIDC Provider — Claude Code Instructions

> Start here. This file holds working notes: status, decisions, gotchas, procedures. It does **not** duplicate the
> reference documents — read them for facts and keep them true:
>
> | Document | Owns |
> |----------|------|
> | `ARCH.md` | architecture: request flows, HEM device API, file tree, Redis schema, security-log events, rate limits, caches |
> | `SECURITY.md` | threat model, trust boundaries (user-signed ID Token, SSO token in the browser), controls, headers, accepted risks |
> | `README.md` | operator documentation: install, deploy, update, release, backup, endpoints, admin API |
> | `PRODUCT.md` | product positioning (public, English) |
> | `../SSO-PLAN.md`, `../REVIEW-2026-09-20.md` | design and review records in the bundle, outside this repo |
>
> A fact that lives in one of those files is linked from here, not copied.

## SDK Reference
HEM SDK = the `hem-sdk-js/` submodule: `README.md`, `EXAMPLES.md`, `hem-sdk.browser.d.ts` (public API and types), `MIGRATION.md` (breaking changes per release). The device endpoints the SDK calls are listed under *HSM API* below. Read only when you need to know the HSM API.

---

## Project Status — Complete

### Backend (`src/`) — 100%
- `GET`/`POST /authorize` — OIDC param validation, serves `signin.html` (POST → 303 to the GET form so signin.js reads the params from the URL); `prompt=none` → `login_required` (the OP has no session)
- `POST /authorize/login` — user lookup (by `sub` or `username`), builds `signing_input`, Redis session TTL 120s
- `POST /authorize/confirm` — Ed25519 verify, assembles JWT, emits code
- `POST /token` — client_secret ALWAYS for confidential clients (Basic or POST) + PKCE S256 when the code has a challenge; `public=true` clients are PKCE-only. `Cache-Control: no-store`. Returns pre-signed `id_token` + `access_token`
- `GET/POST /userinfo` — Bearer token
- `GET /jwks.json` — with 60s in-process cache, invalidated on enrollment
- `GET /.well-known/openid-configuration`
- `GET`/`POST /logout` — RP-initiated logout: `id_token_hint` verified (signature + issuer), `client_id` accepted, `post_logout_redirect_uri` exact-matched against the client's `post_logout_redirect_uris` (legacy origin fallback when the list is empty, logged once). Browsers get `logout.html` (template, placeholders `{{SUB}}`/`{{REDIRECT}}`/`{{RP}}`/`{{TAIL}}` filled by `logoutPage()`) + `logout.js`: asks “also sign out of Encedo?” when the browser holds an SSO session for that `sub` (§2 of RP-Initiated Logout 1.0), clears on Yes only, redirects at once when nothing is kept
- Admin API: full CRUD users + clients
- Enrollment: challenge-response + hardware attestation via api.encedo.com
- Security log: Redis ZSET + stderr dual-write
- Audit log in admin panel: pagination, filtering
- Invite flow (user): `POST /admin/invite` → one-time token → `POST /signup/prefill` + `POST /signup/register` (token always in the JSON body, never `?token=`)
- Invite flow (client): `POST /admin/invite-client` → one-time token → `POST /signup-client/prefill` + `POST /signup-client/register`
- Invites admin API: `GET /admin/invites`, `DELETE /admin/invites/:token`, `DELETE /admin/client-invites/:token`
- **SSO** (2026-09-20): `/authorize/login` takes `sso_iat` (+ `prompt`, `max_age`), answers `sso: {enabled, used, rejected, suggest_seconds, max_seconds}`; ID Token `auth_time`/`amr`; `client.sso`, `user.sso` (default true); env `SSO_ENABLED`/`SSO_MAX_SECONDS`/`SSO_SUGGEST_SECONDS`; `/logout` page (`logout.html` + `logout.js`) asks before clearing `encedo_sso:*` (Yes/No; no question when nothing is kept). Design: `../SSO-PLAN.md`.

### Trusted App (`signin.js`) — 100%
- Login screen — HSM URL only (no username/password fields)
- Step A: `searchKeys(null, 'EXTAID')` — mobile mode detection (SDK anchors + base64-encodes the pattern)
- Step B: `searchKeys(token?, '^ETSOIDC...')` — find OIDC keys
- Auto-select when single key (skip s-keys)
- s-keys screen — key list, selection
- s-confirm screen — shows `preferred_username` (label: "username"), name, email, client name, issuer, iat, exp; user clicks Approve
- s-signing screen — spinner, "Waiting for approval…" + "Use passphrase instead" button
- s-pin screen — passphrase fallback (4xx from HSM or mobile cancel); no RP badge
- `doCancelMobile()` — sets `currentOpId=null`, aborts `mobileAbortCtrl`, switches to passphrase
- `doTryAgain()` — full state reset (all session vars + `currentOpId` + `mobileAbortCtrl` + `cancelRedirect`), returns to s-login; exposed as `window.doTryAgain`
- `finalizeSign()` — shared logic: `/authorize/login` → HSM sign → `/authorize/confirm` → 5s countdown → redirect
- 5→1 countdown before RP redirect; Cancel button stops redirect (code expires naturally after 60s)
- `CLAIM_LABELS` map: `{ preferred_username: 'username' }` — translates JWT claim names to display labels
- Module-level vars: `currentOpId` (Symbol|null), `mobileAbortCtrl` (AbortController|null), `cancelRedirect` (fn|null)
- **SSO accounts screen** (`s-accounts`): `ssoList/ssoSave/ssoForget` over `localStorage` `encedo_sso:<hsm_url>|<kid>`; `doSsoPick()` = getVersion → `/authorize/login` with `sso_iat` → `exdsaSign` with the cached token (401 → drop + fresh `showConfirm` with a note); `showConfirm()` shared by the normal path; `authorizeLifetime()` = suggest_seconds when “remember” ticked; entry saved in `doCompleteSign` after a successful confirm. `HEM_OPTS`: `?hem_broker=` honoured on localhost only (E2E test).

### enrollment.js — 100%
- pubkey converted base64 → hex before sending to backend
- description: `btoa('ETSOIDC' + sub)`
- Fetches attestation `{genuine, crt}` from HSM, sends to backend
- Backend validates via `POST api.encedo.com/attest`
- `hsm_crt` stored in Redis for audit
- ECC keys: `createKeyPair` called with `mode: 'ExDSA'`; DER→P1363 conversion immediately after `exdsaSign`
- `derToP1363(derBytes, keyType)` lives in `hsm-common.js` (one copy for all pages), validates the DER structure and handles short- and long-form lengths (P-521 uses a 3-byte header)
- Success screen: "Go to service" button (redirects to `client_redirect_origin`; hidden if not available)

### signup.js — 100%
- Single-step flow: prefill → HSM enrollment → account creation in one pass
- Calls `/signup/register` (creates user) then `/enrollment/validate` + `/enrollment/submit`
- Locked username and locked key type supported (same UI pattern as enrollment.html)
- Same `derToP1363` (from `hsm-common.js`) + `mode: 'ExDSA'` as enrollment.js
- **Resumable**: once `/signup/register` succeeded the page keeps `{sub, enrollment_token, kid}` in `progress`; a failed HSM step lets the user press the button again without re-registering (the invite is consumed) or creating a second key. A used-up enrollment token after a failed submit is reported as “ask your administrator for a new link”.
- "Go to service" redirects to `client_redirect_origin` from `/signup/register` response

---

## Stack

```
Node.js v22 ESM
Express 4
Redis (node-redis v4) — sole database
crypto (built-in) — Ed25519 verify via SPKI DER reconstruction
No external crypto dependencies
```

## File Structure

Canonical tree: `ARCH.md` §File Structure. What matters when editing: a new UI file goes in **three** places plus the CSP hash list (Known Issues), `hem-sdk-js/` is a submodule (Known Issues), `src/cli/` ships in the image and the ZIP.

---

## Key Architecture Decisions

### signing_input
Backend builds `signing_input = base64url(header).base64url(payload)`.
Frontend only signs — does not build JWT.

### Ed25519 verification in backend
```javascript
// pubkey from Redis: hex-encoded raw 32-byte public key
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const pubkeyDer   = Buffer.concat([SPKI_PREFIX, Buffer.from(pubkeyHex, 'hex')]);
const publicKey   = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
verify(null, Buffer.from(signing_input), publicKey, Buffer.from(signature, 'base64url'));
```

### ECC P-256/P-384/P-521 verification in backend
```javascript
// pubkey in Redis: hex-encoded uncompressed X||Y (64/96/132 bytes)
// SPKI prefixes per curve (uncompressed point: 04 || X || Y):
const EC_SPKI_COMPRESSED_PREFIX = {
  P256: Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
  P384: Buffer.from('3076301006072a8648ce3d020106052b8104002203620004',     'hex'),
  P521: Buffer.from('30819b301006072a8648ce3d020106052b810400230381860004', 'hex'),
};
// stored as uncompressed X||Y hex → prepend 04 for DER SPKI
const pubkeyDer = Buffer.concat([EC_SPKI_COMPRESSED_PREFIX[key_type],
                                  Buffer.from('04', 'hex'),
                                  Buffer.from(pubkeyHex, 'hex')]);
const publicKey = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
verify(null, Buffer.from(signing_input), publicKey, Buffer.from(signature, 'base64url'),
  { dsaEncoding: 'ieee-p1363' });
// Frontend always sends P1363 (r||s fixed-width) — converted from DER right after exdsaSign
```

### exdsaSign in hem-sdk-js
```javascript
// msg = base64 of UTF-8 bytes of signing_input — must be this way, do not change
body.msg = toB64(strToBytes(msg));
// HSM returns standard base64 → convert to base64url for JWT
```

### pubkey encoding
- HSM returns pubkey as **standard base64**
- enrollment.js converts: `atob(keyInfo.pubkey)` → bytes → hex and sends to backend
- **Ed25519**: backend stores raw 32 bytes as hex (64 hex chars)
- **EC (P-256/P-384/P-521)**: HSM returns compressed point (`02`/`03` + X, 33/49/67 bytes)
  - Backend decompresses to uncompressed X||Y (64/96/132 bytes) via `decompressEcKey()` in `enrollment.js`
  - Stored as hex 64/96/132 bytes; JWKS `x`+`y` coordinates extracted from stored uncompressed form
- Compressed pubkey hex lengths: P256=66, P384=98, P521=134 (validated on submit)

### Key description format
```javascript
// At enrollment:
description = btoa('ETSOIDC' + sub)
// Searching OIDC keys (the SDK prefixes '^' and base64-encodes the pattern itself):
searchKeys(token, 'ETSOIDC')
// Mobile detection ('EXTAID' keys):
searchKeys(null, 'EXTAID')
```

### Sub-based user lookup
Backend `/authorize/login` accepts `sub` (direct Redis lookup) or `username` (O(1) via `username_index` hash):
```javascript
if (subParam?.trim()) {
  const raw = await redis.hGetAll(`user:${subParam.trim()}`);
  user = raw?.sub ? raw : null;
} else {
  user = await findUserByUsername(username.trim());
}
```

### hem-sdk-js — HTTP error handling
`#req` catches JSON.parse errors (empty 401 response):
```javascript
try { data = await res.json(); } catch { data = null; }
// then: if (!res.ok) throw new HemError(...)
```
Without this, a 401 with empty body throws SyntaxError instead of HemError — trusted app doesn't recognise it as 4xx.

### Mobile cancel — currentOpId + mobileAbortCtrl
```javascript
let currentOpId = null;
let mobileAbortCtrl = null;
// before authorizeRemote:
const opId = Symbol();
currentOpId = opId;
mobileAbortCtrl = new AbortController();
// after return:
if (currentOpId !== opId) return; // cancelled
// doCancelMobile():
currentOpId = null;
mobileAbortCtrl?.abort(); mobileAbortCtrl = null;
// authorizeRemote accepts { signal } — aborts broker polling immediately
```

### JWKS cache
Module-level `jwksCache` variable in `oidc.js`, 60s TTL. Invalidated immediately after successful enrollment via `invalidateJwksCache()` exported from `oidc.js`.

### Attestation validation
`src/services/attestation.js` POSTs `{genuine, crt}` to `https://api.encedo.com/attest`.
Checks `result === 'ok'` — timestamp validation delegated entirely to `api.encedo.com` (local check removed to avoid clock-skew false negatives).
`crt` (X.509 PEM) stored as `hsm_crt` in Redis. Debug logging active (intended — useful in production for tracing).

**Attestation v2 (roadmap — WAITING FOR OFFICIAL FIRMWARE):** the new HSM firmware will ship advanced
attestation as a single **signed JWT** (firmware + hardware + bootloader + the key's KID + proof-of-possession,
signed by the device attestation key rooted in the production-line PKI; KID = SHA256 of the public key,
so the whole chain is verifiable). That lets attestation become **offline-verifiable** (no api.encedo.com
round-trip) and a **hard enrollment gate** bound to the exact key. The signed JWT will be stored in Redis
for evidence (not just the `hw_attested` flag), re-attestation is on demand (`POST {nonce,KID}` → JWT), and
the PKI root will be published via api.encedo.com + the website. **Not implemented — pending the production
firmware (currently in testing).** Full design in memory `project_attestation_v2`.

### Email enrollment link + `email_verified`
Server can email the enrollment/invite link over SMTP, and a completed enrollment from an emailed link proves mailbox access → `email_verified`.

- **Mailer** (`src/services/mailer.js`, `nodemailer`): `sendEnrollmentEmail`/`sendVerificationEmail`. Transport gated on `SMTP_HOST`+`MAIL_FROM` (`isMailEnabled()`); `SMTP_MODE=ssl` (465, implicit TLS) or `starttls` (587, `requireTLS` — no silent plaintext fallback). **DKIM/SPF/DMARC is entirely the mail server's job** — the app signs nothing, only supplies to/from/subject/body. Sender never throws (a send failure must not break account creation; admin has copy-paste fallback). `/health` exposes `mail_enabled`.
- **Nonce → `email_verified`**: an emailed link carries `&n=<email_nonce>` in the URL **fragment** (not in server logs). The nonce lives on `invite:{token}`/`enrollment:{token}` and is **never returned to the admin** (that is what keeps the signal trustworthy — a hand-copied link has no `&n=` → `email_verified` stays false). Two paths: `/enrollment/submit` sets it when `n === session.email_nonce`; `/signup/register` sets `via_email` on the enrollment session when `n === invite.email_nonce`, and `/enrollment/submit` commits it. Stored as `user:{sub}.email_verified='true'|'false'` (upgrade-only — re-enrollment does not degrade it). Exposed as the `email_verified` claim in **id_token + userinfo**.
- **Endpoints**: `POST /admin/invites/:token/send-email` (emails invite link), `POST /admin/users/:sub/send-verification-email` (standalone verify link, `emailVerify.js`), `POST /verify-email/confirm` (public, one-time `getDel`, sets `email_verified=true` if the current email still matches). Admin panel: "Email link" (invite modal) + "Send verification email" (Edit User) buttons, disabled when `mail_enabled=false`.
- **Connector enforcement**: `carbonio-oidc-connector` requires `email_verified===true` before PreAuth when `require_email_verified` is set (403 otherwise).

Caveat (inherent to any email verification): intercepting the mail yields a false `email_verified=true`. The nonce adds no new attack surface — the enrollment token already grants enrollment; the nonce only carries the verification signal.

### Landing page (`/`) vs status page (`/status`)

`index.html` (operator status: running / issuer / discovery / build) moved to **`/status`**, where it is served on **every** instance. `/` serves `landing.html` **only when `LANDING_PAGE=1`** — a per-tenant env var, because the public instance (`oidc.encedo.com`) and the test instances (`test.`/`demo.oidc.encedo.com`) run the same image. Unset variable ⇒ `/` still serves the status page, i.e. the test tenants are unchanged.

- **Files**: `landing.html` (inline `<style>`, hashed for CSP) + `landing.js` (external — CSP is `script-src 'self'`).
- **Deliberately dark-themed**, and dark unconditionally (`color-scheme: dark`, one palette on `:root`). Every other screen stays light; the landing is a product surface, not an operator one. Palette derives from the brand: paper = the logo's navy taken deeper (`#14103a`), purple `#6E358C` lifted to `#b98fd4` so it carries text on navy, amber `#f5b041` used exactly once (self-host block). Primary button uses **dark text on purple** — white on the lifted purple is the one low-contrast combination on the page.
- `logo.png` is an 8-bit palette PNG with **no alpha**, so on dark it sits on an explicit white chip (a bare `<img>` looks like a rendering fault).
- The hero demonstration is **real**: the page generates a throwaway Ed25519 pair via WebCrypto, signs the `signing_input` it prints, and verifies it. Without WebCrypto Ed25519 (Chrome <105 / Firefox <113) the row still fills from random bytes but drops the word `valid` — it must not claim a verification that did not happen.
- The rail reads `issuer` + `commit` from `/health` (same source as `index.js`); on failure the static markup values stay.
- Layout is adapted from `~/develop/chat/encedo-chat/impl/web/landing.html` (onchato); content is backed by `PRODUCT.md`.

---

## Redis Schema

Canonical: `ARCH.md` §Redis Schema (every key, field and TTL). Semantics that are easy to get wrong:

- `user.email_verified` is upgrade-only: set by an emailed link's nonce or `/verify-email/confirm`, never lowered by re-enrollment; an admin email change resets it to `'false'`.
- `client.allow_any_user` lets any **enrolled** user sign in to that client; it never creates identities. The login gate ORs it with `user.clients[]`.
- `email_index` was introduced after the first users existed: records created before it are not backfilled and get indexed on their next email change.
- `invite.email_nonce` is never returned to the admin; that is what makes `email_verified` mean “the mailbox received the link”.

---

## Trusted App — Detailed Flow

```
doLogin()
  → hemCheckin()
  → Step A: searchKeys(null, 'EXTAID')
      ok  → session.openSearch=true, session.hasMobileApp=(keys.length>0)
      4xx → session.openSearch=false → showPinScreen() [pendingAfterPin='search']
  → Step B (only if openSearch):
      searchKeys(null, '^ETSOIDC...')
      zero keys → error
      one key   → doSelectKey()
      many keys → showScreen('s-keys')

doSubmitPin()             ← user entered passphrase
  pendingAfterPin='search':
    authorizePassword → searchKeys → renderKeyList → doSelectKey()
  pendingAfterPin='use':
    session.password=passphrase → doSelectKey()

doSelectKey()
  session.password → authorizePassword(scope) → finalizeSign()
  session.hasMobileApp → showScreen('s-signing') with cancel btn
                       → authorizeRemote(scope) → if cancelled → ignore
                       → finalizeSign()
  else → showPinScreen() [pendingAfterPin='use']

doCancelMobile()
  currentOpId=null
  session.password → doSelectKey()
  else → showPinScreen() [pendingAfterPin='use']

finalizeSign(useToken, kid, label)
  → POST /authorize/login → { session_id, signing_input }
  → hem.exdsaSign(useToken, kid, signing_input) → signature (base64url)
  → POST /authorize/confirm → { redirect_url }
  → countdown 5s → window.location.href = redirect_url
```

---

## HSM API (Encedo HEM)

Canonical: `ARCH.md` §HEM device API used by the pages. Full surface: `hem-sdk-js/hem-sdk.browser.d.ts`.

---

## Security State

All critical and high severity issues resolved. See `SECURITY.md` for full model.

Open (accepted or delegated):
- `GET /authorize` rate limit → nginx `limit_req`
- id_token not revocable → OIDC spec limitation, configure short TTL
- Admin panel: secret is per-tab (`sessionStorage`) + “Forget secret” button (2026-09-20)
- Redis TLS → ops configuration (`rediss://`)
- **ID Token signed by the user's key** (design): RPs trust it only as the `/token` response — documented in SECURITY.md / README; never "fix" this in code
- No RS256 (HSM has no RSA) — documented, not fixable
- 2026-09-20 review: all packages deployed, including per-tenant Redis network + `requirepass` (M13) and enrollment/invite tokens in POST bodies (M16). Report: `../REVIEW-2026-09-20.md`

---

## Admin Panel — Key Details

- `connectAndSave()` — saves API base URL to localStorage and the secret to **sessionStorage** (dies with the tab; “Forget secret” button clears it), reloads page
- `checkHealth()` — fetches `/health`, sets green/orange indicator (orange = URL ok but secret invalid), populates version label
- `checkHealthDebounced()` — 600ms debounce wrapper on the API-base `input` event; the secret field is only sent on Enter (never on keystroke)
- Default API base = `window.location.origin` (not hardcoded localhost — critical for multi-tenant)
- Version label in sidebar: `' v ' + commit` (space before v)
- `ADMIN_ALLOWED_IPS` lists the **admin networks** (workstation / VPN), because with `TRUST_PROXY=1` (mandatory behind nginx) `req.ip` is the real client. Only WITHOUT `TRUST_PROXY` would the nginx container address (172.16/12) show up — and then every per-IP limit is one shared bucket, so that is a misconfiguration, not something to allow-list. The server warns once when it sees `X-Forwarded-For` without `TRUST_PROXY`.
- **Invites page**: merged table of user + client invites from `GET /admin/invites`; TYPE badge (user=green, client=purple)
- **No inline handlers anywhere** (CSP has no `script-src-attr`): every clickable element carries `data-action="…"`, arguments ride in `data-*` attributes (row index into `_usersCache`/`_clientsCache`, element id), and one delegated `click` listener maps them through the `ACTIONS` table at the bottom of `admin-panel.js`. Same pattern in `signin.js`, `signup.js`, `enrollment.js`, `signup-client.js`. Never put data into an `onclick` string — that was the stored-XSS vector via client `name` (fixed 2026-09-20). `esc()` escapes `'` too; `toast()` uses `textContent`.
- **Invite user button**: on Users page header; opens modal; sends `POST /admin/invite`; shows one-time URL
- **Invite client button**: on Clients page header; opens modal with optional note; sends `POST /admin/invite-client`; shows one-time URL

## Multi-Tenant Docker Architecture

```
nginx container  (nginx/docker-compose.yml)   ports 80+443, shared oidc-net
per-tenant/      (tenants/docker-compose.yml template)
  redis-${TENANT}   redis:7-alpine, --requirepass ${REDIS_PASSWORD}, volume redis-${TENANT}-data,
                    ONLY on oidc-${TENANT}-internal (internal: true)
  oidc-${TENANT}    encedo-oidc:latest, env_file: .env, on oidc-net + oidc-${TENANT}-internal;
                    REDIS_URL set by compose from REDIS_PASSWORD (overrides .env)
```
Tenants created before 2026-09-20 had Redis on `oidc-net` without a password; the one-time migration in README
§*Isolate each tenant's Redis* was run on test, demo and prod on 2026-09-20 (backups in `/var/backups/oidc/pre-isolate-*`).
Hand-run `redis-cli` on the server needs `-a "$REDIS_PASSWORD"` from the tenant `.env`.

- Build: `docker build --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) -t encedo-oidc:latest .`
- SSL: `--standalone` for initial cert, `--webroot` for renewal
- Renewal hook: `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh` → `docker exec nginx nginx -s reload`
- Wildcard DNS `*.oidc.encedo.com A <ip>` — unknown subdomains show SSL error (no wildcard cert, accepted)

## CSP Hashes

Inline `<style>` hashes in `src/app.js` (`STYLE_HASHES`) — 9 files: signin.html, enrollment.html, admin-panel.html, index.html, landing.html, signup.html, signup-client.html, verify-email.html, logout.html.
Run `node update-csp-hashes.js` after any `<style>` block change.
JS must be in external files (CSP `script-src 'self'`) — no inline `<script>` blocks and no `on*=` attributes (there is no `script-src-attr`, so the browser blocks them). Wire clicks through `data-action` + the page's `ACTIONS` map.

---

## Testing

- `npm test` = `test/*.test.js` (node --test): validators, hsm-common, OIDC flows against a spawned app + Redis with a software key. No browser, no HEM.
- `node test/e2e/sso.mjs` = browser E2E of the sign-in page (headless Chromium over CDP) with **`test/e2e/fake-hem.mjs`** — a fake device + broker + RP callback that verifies the SDK's eJWT, issues tokens with the requested lifetime and signs with a software Ed25519 key. Covers SSO flows A/B/C, fallback on device 401, `prompt=login`/`max_age`, `user.sso=false`. Needs `chromium` (or `CHROME=`) and `redis-server`. Runs in CI as the separate `e2e` job (`ci.yml`; the checkout needs the SDK submodule or the page has no SDK and the flow times out on the first screen). The browser is closed through CDP, not a signal: a snap chromium survives `kill` and its profile would carry the cached session into the next run, so the harness also refuses to start when the CDP port is busy. Extend it before touching `signin.js` or `logout.js` — it is the only automated test of those files.

## Known Issues / Notes

Relying-party specifics (Nextcloud `user_oidc`, Carbonio) are **not** kept here — each integration has its own repository. This list is about the provider itself.

1. Ed25519 Web Crypto: Chrome 105+ / Firefox 113+ required (enrollment.html uses Web Crypto)
2. HEM SDK `searchKeys` without token — default HSM config allows open search; 4xx = auth required
3. Attestation debug logging is intentional — useful in production for tracing enrollment issues
4. Server hiccup (SSH freeze, 503) on 1CPU/1GB VM — suspected Redis BGSAVE I/O spikes (3 instances × every 60s). Since 2026-09-20 the Redis client reconnects forever after the first successful connect (before: 10 tries ≈ 3.5 s, then the client closed for good while `/health` kept saying ok), `/health` PINGs Redis and answers 503 when it is down, and the image has a `HEALTHCHECK` on it.
5. ECC `derToP1363`: P-521 DER uses long-form length (`30 81 xx`) — parser handles both short and long form
6. ECC pubkey decompression (`decompressEcKey`) uses Node.js built-in `ECDH.convertKey()` — no external deps
7. "Go to service" button in enrollment.html hidden for admin-triggered re-enrollment (no `client_redirect_origin` in session)
8. ⚠️ **A new UI file must be added to THREE places**, not one: `src/app.js` (route), `Dockerfile` (`COPY` list) and `.github/workflows/release.yml` (zip list). Both build lists name every HTML/JS asset explicitly — a page missing from them is absent from the image / release, and `res.sendFile` then fails at runtime on a server that looks correctly deployed. This is how `landing.html` shipped broken on the first rebuild. Plus `node update-csp-hashes.js` for the inline `<style>` (its `FILES` list is a fourth place; `logout.html` is a template read by `logoutPage()` in `src/routes/oidc.js` rather than a route, but it needs the other three all the same).
9. **`hem-sdk-js/` is a git submodule** (`encedo/hem-sdk-js`, HTTPS in `.gitmodules`; push it over SSH via a local `pushurl`). `git clone --recurse-submodules` (or `git submodule update --init`) before `npm start` / `docker build` — an empty submodule makes `/hem-sdk.js` 404 and the Dockerfile `COPY` fail. The SDK is edited **only** in that repo (its own `CLAUDE.md`: rebuild the bundle with rollup, commit source + bundle + `.d.ts` together); here we only bump the pinned commit. Upstream `MIGRATION.md` lists the breaking changes per SDK release.
10. ⚠️ **File modes travel into the image.** `COPY` keeps the checkout's modes and the container runs as `node`. A `git pull` on the server done with umask 077 (2026-09-21) left 14 files at 0600 → `EACCES` on `src/app.js` → all three tenants in a restart loop (502) for 10 minutes. The Dockerfile now runs `chmod -R a+rX /app` before `USER node`, so this cannot recur from a rebuild — but a **restart never fixes a bad image**: diagnose with `docker logs`, then rebuild + recreate.

---

## Release Process

Canonical procedure: README §*Releasing*. Versions are semver tags `vX.Y.Z`; `package.json` carries the same number and `/health` reports it as `version` next to `commit`. Current: **v1.1.0** (2026-09-21).

```bash
npm version 1.2.0 --no-git-tag-version && git commit -am "release: v1.2.0"
git tag -a v1.2.0 -m "v1.2.0"
git push origin main v1.2.0      # a bare `git push` does NOT send the tag -- and without the tag release.yml never runs
```

`release.yml` (tag `v*`): tests with redis-server → ZIP → GitHub Release with generated notes. `ci.yml` (push to main / PR): lint + `npm test` + the `e2e` job. Verify with `git ls-remote --tags origin` and `gh run list`, never with the local tag list. Deploy from the tag (README §*Updating*) and confirm with `/health`.
