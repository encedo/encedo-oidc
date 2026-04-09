# Encedo OIDC Provider — Claude Code Instructions

## SDK Reference
HEM SDK documentation: `~/develop/sdk-php/HEM.php`
Read only when you need to know the HSM API.

---

## Project Status — Complete

### Backend (`src/`) — 100%
- `GET /authorize` — OIDC param validation, serves `signin.html`
- `POST /authorize/login` — user lookup (by `sub` or `username`), builds `signing_input`, Redis session TTL 120s
- `POST /authorize/confirm` — Ed25519 verify, assembles JWT, emits code
- `POST /token` — PKCE S256, returns pre-signed `id_token` + `access_token`
- `GET/POST /userinfo` — Bearer token
- `GET /jwks.json` — with 60s in-process cache, invalidated on enrollment
- `GET /.well-known/openid-configuration`
- `GET /logout` — RP-initiated logout with Ed25519 signature verification + issuer check
- Admin API: full CRUD users + clients
- Enrollment: challenge-response + hardware attestation via api.encedo.com
- Security log: Redis ZSET + stderr dual-write
- Audit log in admin panel: pagination, filtering
- Invite flow (user): `POST /admin/invite` → one-time token → `GET /signup/prefill` + `POST /signup/register`
- Invite flow (client): `POST /admin/invite-client` → one-time token → `GET /signup-client/prefill` + `POST /signup-client/register`
- Invites admin API: `GET /admin/invites`, `DELETE /admin/invites/:token`, `DELETE /admin/client-invites/:token`

### Trusted App (`signin.js`) — 100%
- Login screen — HSM URL only (no username/password fields)
- Step A: `searchKeys(null, '^RVhUQUlE')` — mobile mode detection
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

### enrollment.js — 100%
- pubkey converted base64 → hex before sending to backend
- description: `btoa('ETSOIDC' + sub)`
- Fetches attestation `{genuine, crt}` from HSM, sends to backend
- Backend validates via `POST api.encedo.com/attest`
- `hsm_crt` stored in Redis for audit

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
├── index.html                  ← Landing page: status, issuer, discovery link, version
├── index.js                    ← Landing page JS (fetches /health)
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
├── hem-sdk.js                  ← Encedo HEM JavaScript SDK
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

### exdsaSign in hem-sdk.js
```javascript
// msg = base64 of UTF-8 bytes of signing_input — must be this way, do not change
body.msg = toB64(strToBytes(msg));
// HSM returns standard base64 → convert to base64url for JWT
```

### pubkey encoding
- HSM returns pubkey as **standard base64**
- Backend stores as **hex** (32 raw bytes)
- enrollment.js converts: `atob(keyInfo.pubkey)` → bytes → hex

### Key description format
```javascript
// At enrollment:
description = btoa('ETSOIDC' + sub)
// Searching OIDC keys:
searchKeys(token, '^' + btoa('ETSOIDC'))
// Mobile detection:
searchKeys(null, '^RVhUQUlE')
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

### hem-sdk.js — HTTP error handling
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
Checks: `result === 'ok'`, timestamp not in future (±5s), not older than 15s.
`crt` (X.509 PEM) stored as `hsm_crt` in Redis. Debug logging active (intended — useful in production for tracing).

---

## Redis Schema

```
user:{sub}        Hash { sub, username, name, email, hsm_url,
                        kid, pubkey, hw_attested, hsm_crt,
                        clients (JSON array), enrollment_token,
                        enrolled_at, created_at, updated_at }

username_index    Hash { username → sub }

users             Set  { sub, ... }

client:{id}       Hash { client_id, client_secret, name,
                        redirect_uris, scopes, pkce,
                        id_token_ttl, access_token_ttl, created_at }

pending:{sid}     JSON TTL 120s
code:{code}       JSON TTL 60s
access:{token}    JSON TTL = access_token_ttl

user_tokens:{sub} Set  { access:{token}, ... }
enrollment:{tok}  JSON TTL 24h → 30min after validate
enroll_lock:{sub} String TTL 30s  (NX lock)
invite:{token}    JSON TTL 24h  { client_id, client_name, username, name, email }
client-invite:{token} JSON TTL 24h  { note }
security:log      ZSet score=ms  value=JSON  (cap 20 000)
security:events   Pub/Sub channel
```

---

## Trusted App — Detailed Flow

```
doLogin()
  → hemCheckin()
  → Step A: searchKeys(null, '^RVhUQUlE')
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
- Admin panel browser logout button → missing, low priority
- Redis TLS → ops configuration (`rediss://`)

---

## Admin Panel — Key Details

- `connectAndSave()` — saves API base URL + secret to localStorage, reloads page
- `checkHealth()` — fetches `/health`, sets green/orange indicator (orange = URL ok but secret invalid), populates version label
- `checkHealthDebounced()` — 600ms debounce wrapper; used on `oninput` to avoid CSP errors on partial URLs
- Default API base = `window.location.origin` (not hardcoded localhost — critical for multi-tenant)
- Version label in sidebar: `' v ' + commit` (space before v)
- `ADMIN_ALLOWED_IPS` must include `172.16.0.0/12` for Docker nginx reverse proxy
- **Invites page**: merged table of user + client invites from `GET /admin/invites`; TYPE badge (user=green, client=purple); Delete button uses `data-inv-type` + `data-inv-token` attributes (no XSS via onclick)
- **Invite user button**: on Users page header; opens modal; sends `POST /admin/invite`; shows one-time URL
- **Invite client button**: on Clients page header; opens modal with optional note; sends `POST /admin/invite-client`; shows one-time URL

## Multi-Tenant Docker Architecture

```
nginx container  (nginx/docker-compose.yml)   ports 80+443, shared oidc-net
per-tenant/      (tenants/docker-compose.yml template)
  redis-${TENANT}   redis:7-alpine, volume redis-${TENANT}-data
  oidc-${TENANT}    encedo-oidc:latest, env_file: .env
```

- Build: `docker build --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) -t encedo-oidc:latest .`
- SSL: `--standalone` for initial cert, `--webroot` for renewal
- Renewal hook: `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh` → `docker exec nginx nginx -s reload`
- Wildcard DNS `*.oidc.encedo.com A <ip>` — unknown subdomains show SSL error (no wildcard cert, accepted)

## CSP Hashes

Inline `<style>` hashes in `src/app.js` (`STYLE_HASHES`) — 6 files: signin.html, enrollment.html, admin-panel.html, index.html, signup.html, signup-client.html.
Run `node update-csp-hashes.js` after any `<style>` block change.
JS must be in external files (CSP `script-src 'self'`) — no inline `<script>` blocks.

---

## Known Issues / Notes

1. Nextcloud requires `allow_local_remote_servers = true` and `allow_insecure_http = 1` for dev
2. Nextcloud `redirect_uri`: `http://localhost:8080/index.php/apps/user_oidc/code`
3. JWKS cache in Nextcloud ignores `kid` — patch described in `nextcloud-jwks-kid-patch.md`
4. Ed25519 Web Crypto: Chrome 105+ / Firefox 113+ required (enrollment.html uses Web Crypto)
5. HEM SDK `searchKeys` without token — default HSM config allows open search; 4xx = auth required
6. Attestation debug logging is intentional — useful in production for tracing enrollment issues
7. Server hiccup (SSH freeze, 503) on 1CPU/1GB VM — suspected Redis BGSAVE I/O spikes (3 instances × every 60s)

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
