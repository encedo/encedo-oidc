# Encedo OIDC Provider — Claude Code Instructions

## SDK Reference
HEM SDK documentation: `~/develop/sdk-php/HEM.php`
Read only when you need to know the HSM API.

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
- `GET`/`POST /logout` — RP-initiated logout: `id_token_hint` verified (signature + issuer), `client_id` accepted, `post_logout_redirect_uri` exact-matched against the client's `post_logout_redirect_uris` (legacy origin fallback when the list is empty, logged once)
- Admin API: full CRUD users + clients
- Enrollment: challenge-response + hardware attestation via api.encedo.com
- Security log: Redis ZSET + stderr dual-write
- Audit log in admin panel: pagination, filtering
- Invite flow (user): `POST /admin/invite` → one-time token → `POST /signup/prefill` + `POST /signup/register` (token always in the JSON body, never `?token=`)
- Invite flow (client): `POST /admin/invite-client` → one-time token → `POST /signup-client/prefill` + `POST /signup-client/register`
- Invites admin API: `GET /admin/invites`, `DELETE /admin/invites/:token`, `DELETE /admin/client-invites/:token`
- **SSO** (2026-09-20): `/authorize/login` takes `sso_iat` (+ `prompt`, `max_age`), answers `sso: {enabled, used, rejected, suggest_seconds, max_seconds}`; ID Token `auth_time`/`amr`; `client.sso`, `user.sso` (default true); env `SSO_ENABLED`/`SSO_MAX_SECONDS`/`SSO_SUGGEST_SECONDS`; `/logout` page + `logout.js` clears `encedo_sso:*`. Design: `../SSO-PLAN.md`.

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

```
encedo-oidc/
├── src/
│   ├── app.js                  ← Express app, CSP, routes; /health returns {status,ts,commit,issuer}
│   ├── routes/
│   │   ├── oidc.js             ← all OIDC endpoints + JWKS cache
│   │   ├── enrollment.js       ← HSM key enrollment
│   │   ├── adminUsers.js       ← CRUD + audit log
│   │   ├── adminClients.js
│   │   ├── invite.js           ← user invite flow + admin invites list
│   │   └── inviteClient.js     ← client invite flow
│   ├── middleware/
│   │   ├── auth.js             ← requireAdminAuth + requireAdminNetwork
│   │   ├── rateLimit.js
│   │   ├── validate.js         ← all input validators
│   │   └── errorHandler.js
│   └── services/
│       ├── redis.js
│       ├── securityLog.js      ← dual-write: stderr + Redis ZSET
│       └── attestation.js      ← HSM attestation via api.encedo.com
├── index.html                  ← Status page: status, issuer, discovery link, version (served at /status)
├── index.js                    ← Status page JS (fetches /health)
├── landing.html                ← Public landing page (served at / when LANDING_PAGE=1)
├── landing.js                  ← Landing JS: rail from /health + Ed25519 signing demo
├── hsm-common.js               ← shared by signin/enrollment/signup: key-type maps, derToP1363, JWT decode, fetchJson, hemErrMsg, authorizeScope
├── signin.js                   ← Trusted App logic
├── signin.html                 ← Trusted App shell
├── enrollment.js               ← Enrollment flow logic
├── enrollment.html
├── signup.html                 ← User signup (invite flow)
├── signup.js                   ← User signup JS
├── signup-client.html          ← Client signup (invite flow, no HSM)
├── signup-client.js            ← Client signup JS
├── admin-panel.js
├── admin-panel.html
├── hem-sdk-js/                 ← Encedo HEM JavaScript SDK (git submodule → encedo/hem-sdk-js); hem-sdk.browser.js served at /hem-sdk.js
├── favicon.ico
├── nginx/docker-compose.yml    ← nginx container (shared, ports 80+443, oidc-net)
└── tenants/docker-compose.yml  ← per-tenant template (TENANT env var)
```

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

```
user:{sub}        Hash { sub, username, name, email, email_verified, hsm_url,
                        kid, pubkey, key_type, hw_attested, hsm_crt,
                        clients (JSON array), enrollment_token,
                        enrolled_at, created_at, updated_at }
                  email_verified: 'true'|'false' (default 'false') — 'true' only via emailed-link nonce
                    or /verify-email/confirm; upgrade-only (re-enrollment never degrades it)
                  pubkey: hex raw bytes — Ed25519: 32B (64 hex); EC: uncompressed X||Y — P256: 64B, P384: 96B, P521: 132B
                  key_type: 'Ed25519' | 'P256' | 'P384' | 'P521'

username_index    Hash { username → sub }

email_index       Hash { email(lowercased) → sub }   # uniqueness per tenant; pre-existing records grandfathered (not backfilled)

users             Set  { sub, ... }

client:{id}       Hash { client_id, client_secret, name,
                        redirect_uris, post_logout_redirect_uris, scopes, pkce, public, allow_any_user,
                        id_token_ttl, access_token_ttl, created_at }
                  allow_any_user: 'true'|'false' (default 'false') — open client: any ENROLLED user may
                    authenticate (login gate ORs it with user.clients[]); never auto-creates the identity

pending:{sid}     JSON TTL 120s
code:{code}       JSON TTL 60s
access:{token}    JSON TTL = access_token_ttl

user_tokens:{sub} Set  { access:{token}, ... }
enrollment:{tok}  JSON TTL 24h → 30min after validate
                  { sub, username, forced_key_type, hsm_url, challenge?,
                    client_redirect_origin?, email_nonce?, via_email? }
                  client_redirect_origin set when created via invite flow;
                  email_nonce/via_email carry the email_verified signal (see Email section)
enroll_lock:{sub} String TTL 30s  (NX lock)
invite:{token}    JSON TTL 24h  { client_id/clients, client_name(s), username, name, email, email_nonce? }
                  email_nonce present when server emails the link (&n=); never returned to the admin
client-invite:{token} JSON TTL 24h  { note }
email_verify:{token}  JSON TTL 24h  { sub, email }  ← standalone verify link (Edit User)
security:log      ZSet score=ms  value=JSON  (cap 20 000)
security:events   Pub/Sub channel
```

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

```
POST {hsm_url}/api/checkin                ← hemCheckin()
POST {hsm_url}/api/keymgmt/search         ← searchKeys(token, pattern)
POST {hsm_url}/api/authorize-key-op       ← authorizePassword(pwd, scope) / authorizeRemote(scope)
POST {hsm_url}/api/sign                   ← exdsaSign(token, kid, msg)
GET  {hsm_url}/api/system/config/attestation ← getAttestation(token)
```

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
- Open from the 2026-09-20 review (deployment changes, user's call): per-tenant Redis network + `requirepass` (M13); enrollment/invite token in POST bodies instead of `?token=` (M16). Full list: `../REVIEW-2026-09-20.md`

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
Tenants created before 2026-09-20 still have Redis on `oidc-net` without a password until the one-time
migration in README §*Isolate each tenant's Redis* is run (user does it, one tenant at a time).

- Build: `docker build --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) -t encedo-oidc:latest .`
- SSL: `--standalone` for initial cert, `--webroot` for renewal
- Renewal hook: `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh` → `docker exec nginx nginx -s reload`
- Wildcard DNS `*.oidc.encedo.com A <ip>` — unknown subdomains show SSL error (no wildcard cert, accepted)

## CSP Hashes

Inline `<style>` hashes in `src/app.js` (`STYLE_HASHES`) — 8 files: signin.html, enrollment.html, admin-panel.html, index.html, landing.html, signup.html, signup-client.html, verify-email.html.
Run `node update-csp-hashes.js` after any `<style>` block change.
JS must be in external files (CSP `script-src 'self'`) — no inline `<script>` blocks and no `on*=` attributes (there is no `script-src-attr`, so the browser blocks them). Wire clicks through `data-action` + the page's `ACTIONS` map.

---

## Testing

- `npm test` = `test/*.test.js` (node --test): validators, hsm-common, OIDC flows against a spawned app + Redis with a software key. No browser, no HEM.
- `node test/e2e/sso.mjs` = browser E2E of the sign-in page (headless Chromium over CDP) with **`test/e2e/fake-hem.mjs`** — a fake device + broker + RP callback that verifies the SDK's eJWT, issues tokens with the requested lifetime and signs with a software Ed25519 key. Covers SSO flows A/B/C, fallback on device 401, `prompt=login`/`max_age`, `user.sso=false`. Needs `chromium` (or `CHROME=`) and `redis-server`; not in CI. Extend it before touching `signin.js` — it is the only automated test of that file.

## Known Issues / Notes

1. Nextcloud requires `allow_local_remote_servers = true` and `allow_insecure_http = 1` for dev
2. Nextcloud `redirect_uri`: `http://localhost:8080/index.php/apps/user_oidc/code`
3. JWKS cache in Nextcloud ignores `kid` — patch described in `nextcloud-jwks-kid-patch.md`
4. Ed25519 Web Crypto: Chrome 105+ / Firefox 113+ required (enrollment.html uses Web Crypto)
5. HEM SDK `searchKeys` without token — default HSM config allows open search; 4xx = auth required
6. Attestation debug logging is intentional — useful in production for tracing enrollment issues
7. Server hiccup (SSH freeze, 503) on 1CPU/1GB VM — suspected Redis BGSAVE I/O spikes (3 instances × every 60s). Since 2026-09-20 the Redis client reconnects forever after the first successful connect (before: 10 tries ≈ 3.5 s, then the client closed for good while `/health` kept saying ok), `/health` PINGs Redis and answers 503 when it is down, and the image has a `HEALTHCHECK` on it.
8. ECC `derToP1363`: P-521 DER uses long-form length (`30 81 xx`) — parser handles both short and long form
9. ECC pubkey decompression (`decompressEcKey`) uses Node.js built-in `ECDH.convertKey()` — no external deps
10. "Go to service" button in enrollment.html hidden for admin-triggered re-enrollment (no `client_redirect_origin` in session)
11. ⚠️ **A new UI file must be added to THREE places**, not one: `src/app.js` (route), `Dockerfile` (`COPY` list) and `.github/workflows/release.yml` (zip list). Both build lists name every HTML/JS asset explicitly — a page missing from them is absent from the image / release, and `res.sendFile` then fails at runtime on a server that looks correctly deployed. This is how `landing.html` shipped broken on the first rebuild. Plus `node update-csp-hashes.js` for the inline `<style>`.
12. **`hem-sdk-js/` is a git submodule** (`encedo/hem-sdk-js`, HTTPS in `.gitmodules`; push it over SSH via a local `pushurl`). `git clone --recurse-submodules` (or `git submodule update --init`) before `npm start` / `docker build` — an empty submodule makes `/hem-sdk.js` 404 and the Dockerfile `COPY` fail. The SDK is edited **only** in that repo (its own `CLAUDE.md`: rebuild the bundle with rollup, commit source + bundle + `.d.ts` together); here we only bump the pinned commit. Upstream `MIGRATION.md` lists the breaking changes per SDK release.

---

## Release Process

Automated via GitHub Actions (`.github/workflows/release.yml`).

**To release a new version:**

```bash
git tag v1.0.0
git push --tags
```

**What happens:**
1. GitHub Actions detects tag `v*`
2. Builds ZIP with `npm ci --omit=dev` + `node_modules` + `src/` + all HTML/JS/config files
3. Creates **Release** on GitHub with `encedo-oidc-v1.0.0.zip` attached
4. Auto-generates release notes from commits

**Installation:**
```bash
VERSION=v1.0.0
curl -fsSL https://github.com/encedo/encedo-oidc/releases/download/${VERSION}/encedo-oidc-${VERSION}.zip \
  -o /tmp/encedo-oidc.zip
sudo unzip /tmp/encedo-oidc.zip -d /opt/encedo-oidc
```

**Versioning:** Use semantic versioning (v0.1.0, v1.0.0, v1.1.0, etc.).
