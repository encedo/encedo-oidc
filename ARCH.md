# Architecture — Encedo OIDC Provider

## Overview

```
Browser / Relying Party
        |
        v
+----------------------------------------------+
|  Encedo OIDC Provider  (Node.js / Express)   |
|                                              |
|  OIDC endpoints  ->  src/routes/oidc.js      |
|  Enrollment      ->  src/routes/enrollment.js|
|  Invites/signup  ->  src/routes/invite.js,   |
|                      inviteClient.js         |
|  Email verify   ->  src/routes/emailVerify.js|
|  Admin API       ->  src/routes/adminUsers.js|
|                       src/routes/adminClients|
|                                              |
|  Middleware: auth, rateLimit, validate,      |
|              errorHandler                    |
|  Services:   redis, securityLog, attestation,|
|              jwt, tokens, issuer, mailer,    |
|              client, clientGrant, ed25519    |
+----------+-----------------------------------+
           |
           +-- Redis (sole persistence layer)
           |
           +-- api.encedo.com  (HSM attestation, at enrollment only)
           |
           +-- SMTP server  (optional: enrollment / verification emails)

Browser calls HSM directly (Encedo HEM SDK)
```

The browser (Trusted App, `signin.js`) communicates with the HSM directly over HTTPS. The backend **never** sees the private key — it only verifies signatures (Ed25519, or ECDSA on P-256/P-384/P-521 — the key type is chosen per user at enrollment) using the public key stored in Redis.

---

## Login Flow (detailed)

```
 Browser                     Backend                    HSM
    |                            |                       |
    |-- GET /authorize --------->|                       |
    |<-- signin.html ------------|                       |
    |                            |                       |
    |-- POST /api/system/checkin ----------------------->|
    |-- POST /api/keymgmt/search (EXTAID)  ------------->|
    |-- POST /api/keymgmt/search (ETSOIDC) ------------->|
    |-- POST /api/auth/token (push / passphrase) ------->|
    |                            |                       |
    |-- POST /authorize/login -->|                       |
    |      {sub, client_id,      |                       |
    |       code_challenge}      |                       |
    |                            |-- build signing_input |
    |                            |-- store pending:{sid} |
    |<-- {session_id,            |                       |
    |     signing_input} --------|                       |
    |                            |                       |
    |-- POST /api/crypto/exdsa/sign -------------------->|
    |<-- signature --------------------------------------|
    |                            |                       |
    |-- POST /authorize/confirm->|                       |
    |      {session_id,          |                       |
    |       signature}           |-- verify signature    |
    |                            |-- assemble JWT        |
    |                            |-- store code:{code}   |
    |<-- {redirect_url} ---------|                       |
    |                            |                       |
    [browser redirects to RP with ?code=...]
    |                            |                       |
    RP -- POST /token ---------->|                       |
                                 |-- verify PKCE S256    |
                                 |-- return tokens       |
```

### JWT assembly

The backend builds `signing_input = base64url(header) + '.' + base64url(payload)` and sends it to the browser. The browser passes it to the HSM for signing. The HSM signs raw UTF-8 bytes of the signing_input string. The backend then assembles the full JWT: `signing_input + '.' + base64url(signature)`.

This means the backend controls all JWT claims — the browser cannot forge or modify the payload.

---

## Key Design Decisions

### Public key storage
- HSM returns pubkey as **standard base64**
- Ed25519: backend stores the raw 32 bytes as **hex**; SPKI DER prefix `302a300506032b6570032100` is prepended at verification time
- P-256/P-384/P-521: the HSM returns a compressed point, the backend decompresses it (`ECDH.convertKey`) and stores uncompressed `X||Y` hex; a per-curve SPKI prefix is prepended and the signature is verified as `ieee-p1363` (the page converts the HSM's DER signature right after signing)

### kid derivation
```javascript
kid = SHA1(rawPubkeyBytes).slice(0, 16)  // first 16 bytes = 32 hex chars
```
Matches Encedo HSM convention. SHA-1 second-preimage resistance (~2¹⁶⁰) makes collision attacks infeasible. kid collision is a cosmetic issue (wrong JWKS key returned), not an auth bypass — backend always verifies against the user's specific pubkey from Redis.

### HSM key description
```javascript
// Enrolled with:
description = btoa('ETSOIDC' + sub)

// Searched with:
searchKeys(token, 'ETSOIDC')  // the SDK sends '^' + base64(pattern) -- anchored prefix match
```
This links HSM keys to user subs. Mobile app detection searches for `EXTAID` (sent on the wire as `^RVhUQUlE`).

### EdDSA signing in HEM SDK
```javascript
// msg sent to HSM = base64 of UTF-8 bytes of signing_input
body.msg = toB64(strToBytes(signing_input));
// HSM returns standard base64 signature → convert to base64url for JWT
```

### Enrollment challenge-response
`POST /enrollment/validate` (token in the JSON body) issues a 32-byte random challenge. The frontend signs it with the newly created HSM key and sends `signature` to `/enrollment/submit`. The backend verifies the signature using the submitted pubkey. This proves the enrolling party actually possesses the private key.

### Hardware attestation
```
 Browser / HSM               Backend              api.encedo.com
    |                            |                       |
    |  GET {hsm_url}/api/system/config/attestation       |
    |  <- HSM returns {genuine, crt}                     |
    |                            |                       |
    |-- POST /enrollment/submit->|                       |
    |    {genuine, crt, ...}     |                       |
    |                            |-- POST /attest ------>|
    |                            |<-- {result,           |
    |                            |    timestamp, checks} |
    |                            |-- result === 'ok' ?  |
    |                            |   (freshness checked  |
    |                            |    by api.encedo.com) |
    |                            |-- store hw_attested,  |
    |                            |   hsm_crt in Redis    |
    |<-- {ok, hw_attested} ------|                       |
```

`genuine` is a device-signed blob. `crt` is the X.509 device certificate (contains SKID). Both stored in `user:{sub}` for audit purposes. A failed or absent attestation does **not** block enrollment: `hw_attested` is an advisory flag (see `SECURITY.md`).

---

## File Structure

```
encedo-oidc/
├── src/
│   ├── app.js                    Entry point: Express setup, CSP, routing, /health
│   ├── routes/
│   │   ├── oidc.js               All OIDC endpoints + JWKS cache + discovery + logout page
│   │   ├── enrollment.js         HSM key enrollment (validate + submit)
│   │   ├── invite.js             User invite flow (/admin/invite, /signup/*) + invites list
│   │   ├── inviteClient.js       Client invite flow (/admin/invite-client, /signup-client/*)
│   │   ├── emailVerify.js        Standalone email verification link (/verify-email/confirm)
│   │   ├── adminUsers.js         CRUD /admin/users + custom claims + audit log
│   │   └── adminClients.js       CRUD /admin/clients
│   ├── middleware/
│   │   ├── auth.js               requireAdminAuth + requireAdminNetwork
│   │   ├── rateLimit.js          Redis-backed per-key sliding window
│   │   ├── validate.js           Input validators (email, url, pkce, sig, ...)
│   │   └── errorHandler.js       Central Express error handler
│   ├── services/
│   │   ├── redis.js              Singleton Redis client (node-redis v4), reconnects forever
│   │   ├── securityLog.js        Security event log (Redis ZSET + stderr + Pub/Sub)
│   │   ├── attestation.js        HSM attestation validation via api.encedo.com
│   │   ├── jwt.js                JWT helpers: signature verification per key type, JWK building
│   │   ├── tokens.js             Access-token bookkeeping and per-user revocation
│   │   ├── issuer.js             Issuer URL resolution
│   │   ├── mailer.js             SMTP (nodemailer): enrollment / verification emails
│   │   ├── client.js             Client credential + redirect-URI helpers
│   │   ├── clientGrant.js        Normalises a user's clients[] grant
│   │   └── ed25519.js            Ed25519 helpers
│   └── cli/
│       ├── backup.js             Redis backup (SCAN + DUMP -> gzipped NDJSON)
│       ├── restore.js            Redis restore (validates, then RESTORE with TTLs)
│       └── common.js
├── index.html / index.js         Status page (served at /status, and at / unless LANDING_PAGE=1)
├── landing.html / landing.js     Product landing page (served at / when LANDING_PAGE=1)
├── signin.html / signin.js       Trusted App: sign-in page + SSO account chooser (served at /authorize)
├── logout.html / logout.js       Sign-out page: asks before ending the browser's SSO session
├── enrollment.html / enrollment.js   Enrollment flow
├── signup.html / signup.js       User signup from an invite
├── signup-client.html / signup-client.js   Client signup from an invite
├── verify-email.html / verify-email.js     Email verification link
├── admin-panel.html / admin-panel.js       Admin panel
├── hsm-common.js                 Shared browser helpers (key-type maps, DER→P1363, JWT decode, fetchJson)
├── hem-sdk-js/                   Encedo HEM JavaScript SDK (git submodule → encedo/hem-sdk-js);
│                                 hem-sdk.browser.js is served at /hem-sdk.js
├── update-csp-hashes.js          Recomputes the CSP hashes of every inline <style> into src/app.js
├── rp-server.mjs                 Test Relying Party (port 9876)
├── test/                         node --test suites + test/e2e (browser E2E with a fake HEM)
├── .github/workflows/            ci.yml (lint, tests, E2E on push/PR) · release.yml (ZIP + GitHub Release on tag)
├── Dockerfile                    node:22-alpine, runs as `node`, tree made world-readable at build time
├── nginx/docker-compose.yml      Shared nginx container (multi-tenant)
└── tenants/docker-compose.yml    Per-tenant template (OIDC + private Redis)
```

---

## Single sign-on

```
browser (OP origin localStorage)           OP server                      HEM
 encedo_sso:<hsm_url>|<kid> = {token,iat,exp,sub,…}
   │  /authorize (client B)
   ├─ accounts screen ── click ─────────►  /authorize/login {sub, sso_iat}
   │                                       policy: SSO_ENABLED ∧ client.sso ∧ user.sso
   │                                               ∧ age ≤ SSO_MAX ∧ ¬prompt=login ∧ age ≤ max_age
   │                       ◄── signing_input (auth_time = iat, amr = [hwk,sso]) ──┤
   ├─ getVersion (reachable?) ───────────────────────────────────────────────────►
   ├─ exdsaSign(cached token) ──────────────────────────────────────────────────►  401 → drop entry, fresh sign-in
   └─ /authorize/confirm ──────────────►  code → redirect
```
The token never leaves the browser. `/logout` serves `logout.html` + `logout.js`: when the browser still holds a session for the signed-out user, the page asks whether to end that session too (OpenID Connect RP-Initiated Logout 1.0 §2) and removes the entries only on *Yes*; either answer then follows the permitted post-logout redirect. With nothing kept it redirects at once.

---

## HEM device API used by the pages

The browser talks to the user's device through the HEM SDK (`hem-sdk-js/`, served as `/hem-sdk.js`). The pages use this subset; `test/e2e/fake-hem.mjs` implements exactly it.

```
POST {hsm_url}/api/system/checkin             hemCheckin()
GET  {hsm_url}/api/system/version             getVersion()  -- SSO: "is the device reachable?" before a one-click sign-in
POST {hsm_url}/api/keymgmt/search             searchKeys(token, pattern)  -- 'EXTAID' (mobile app present?), 'ETSOIDC<sub>' (OIDC keys)
POST {hsm_url}/api/keymgmt/create             createKeyPair()  -- enrollment
POST {hsm_url}/api/auth/token                 authorizePassword(pwd, scope) / authorizeRemote(scope)  -- key-use token, lifetime chosen on the device
POST {hsm_url}/api/crypto/exdsa/sign          exdsaSign(token, kid, msg)  -- msg = base64 of the UTF-8 signing_input
GET  {hsm_url}/api/system/config/attestation  getAttestation(token)
```

---

## Redis Schema

```
user:{sub}               Hash
  sub                    UUID
  username               string (indexed in username_index)
  name                   string
  email                  string (lowercase; indexed in email_index)
  email_verified         'true' | 'false'  -- 'true' only via an emailed link's nonce or /verify-email/confirm; never downgraded by re-enrollment
  hsm_url                HTTPS URL of HSM
  hsm_url_in_userinfo    '1' | '0'  (default '1': expose hsm_url in userinfo)
  key_type               'Ed25519' | 'P256' | 'P384' | 'P521'
  kid                    hex — SHA1(pubkey)[:16 bytes]
  pubkey                 hex — Ed25519: raw 32 bytes; EC: uncompressed X||Y (64/96/132 bytes)
  hw_attested            'true' | 'false'
  hsm_crt                PEM X.509 device certificate (from enrollment)
  clients                JSON array of client_id strings
  custom_claims          JSON object of extra claims for id_token/userinfo
  sso                    'false' to forbid single sign-on for this user (absent = allowed)
  enrollment_token       base64url — present until enrollment completes
  enrolled_at            ISO 8601
  created_at             ISO 8601
  updated_at             ISO 8601

username_index           Hash  { username → sub }   (O(1) lookup)
email_index              Hash  { email → sub }      (uniqueness; records created before the index are not backfilled)

users                    Set   { sub, sub, ... }
clients                  Set   { client_id, ... }

client:{client_id}       Hash
  client_id, name
  client_secret          stored in plain text — use strong random value
  redirect_uris          JSON array
  post_logout_redirect_uris JSON array       -- exact-match targets for /logout (empty = origin of redirect_uris, legacy)
  scopes                 JSON array
  pkce                   'true' | 'false'   -- PKCE required at /authorize
  public                 'true' | 'false'   -- no secret, PKCE only (token_endpoint_auth_method=none); default false: secret always required
  allow_any_user         'true' | 'false'   -- open client: any ENROLLED user may authenticate (never auto-creates the identity)
  sso                    'true' | 'false'   -- single sign-on allowed for this client (default true)
  id_token_ttl           seconds (integer string)
  access_token_ttl       seconds (integer string)
  created_at             ISO 8601

pending:{session_id}     JSON  TTL 120s
  sub, kid, client_id, scope, nonce
  redirect_uri, code_challenge, code_challenge_method
  signing_input, state, auth_time, amr

code:{code}              JSON  TTL 60s
  sub, client_id, scope, nonce
  code_challenge, redirect_uri, id_token

access:{token}           JSON  TTL = access_token_ttl
  sub, client_id, scope

user_tokens:{sub}        Set   { access:{token}, ... }  TTL = max(token TTL)

enrollment:{token}       JSON  TTL 24h → 30 min after validate
  sub, username, forced_key_type, hsm_url, challenge?,
  client_redirect_origin?, email_nonce?, via_email?

enroll_lock:{sub}        String TTL 30s  (Redis NX lock, one enrollment at a time)

invite:{token}           JSON  TTL 24h  { clients, client_name(s), username, name, email, email_nonce? }
client-invite:{token}    JSON  TTL 24h  { note }
email_verify:{token}     JSON  TTL 24h  { sub, email }   -- standalone verification link

rl:{prefix}:{key}        String  rate-limit counters, always created with their TTL

security:log             ZSet  score=ms_timestamp  value=JSON event
                               capped at SECURITY_LOG_MAX (default 20 000) entries

security:events          Pub/Sub channel  (same JSON events, real-time)
```

---

## Security Log Events

Defined in `src/services/securityLog.js`:

| Type | Trigger |
|------|---------|
| `auth.login.ok` | Successful /authorize/login |
| `auth.login.fail` | Unknown user or incomplete enrollment |
| `auth.signature.ok` | Valid Ed25519 signature in /authorize/confirm |
| `auth.signature.fail` | Invalid signature |
| `auth.token.issued` | Successful /token exchange |
| `auth.logout` | RP-initiated logout |
| `enrollment.ok` | HSM key enrolled successfully |
| `enrollment.fail` | Enrollment failure (invalid token, sig, duplicate key, …) |
| `enrollment.regen` | Admin regenerated enrollment link |
| `enrollment.email_sent` | Enrollment / invite link emailed |
| `email.verify_sent` | Standalone verification email sent |
| `email.verified` | `/verify-email/confirm` accepted, `email_verified=true` |
| `admin.auth.fail` | Wrong ADMIN_SECRET |
| `admin.user.create` | User created |
| `admin.user.patch` | User updated |
| `admin.user.delete` | User deleted |
| `admin.client.create` | Client created |
| `admin.client.patch` | Client updated |
| `admin.client.delete` | Client deleted |
| `admin.client.rotate_secret` | Client secret rotated |
| `ratelimit.hit` | A rate limit refused a request (key hashed unless it is an IP or UUID) |

Events are written to **stderr** (synchronous, captured by journald/Docker) and to the Redis ZSET (accessible via admin panel audit log).

---

## Rate Limits

Applied per endpoint via `src/middleware/rateLimit.js` (sliding window, Redis-backed):

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /authorize/login` | 20 + 40 | 60s | `client_id`, plus an IP backstop |
| `POST /authorize/confirm` | 10 | 60s | IP |
| `POST /token` | 20 | 60s | IP |
| `GET`/`POST /logout` | 20 | 60s | IP |
| `POST /enrollment/validate` | 10 + 30 | 60s | enrollment token, plus an IP backstop |
| `POST /enrollment/submit` | 5 + 20 | 60s | enrollment token, plus an IP backstop |
| `POST /verify-email/confirm` | 20 | 60s | IP |
| `/admin/*` (authenticated) | 60 | 60s | IP |
| `/admin/*` failed authentications | 10 | 60s | IP — then every admin call from that IP is 429 until the window passes |

`GET /userinfo` and `GET /authorize` are not rate-limited at application level. The limiter is fail-open (see `SECURITY.md`).

Additionally, nginx `limit_req` should be configured upstream (see README) to rate-limit `GET /authorize` and provide a second line of defence.

---

## JWKS Cache

`GET /jwks.json` builds the key list from all users in Redis. To avoid an O(n) Redis read on every OIDC discovery request, the result is cached in-process for 60 seconds. The cache is invalidated immediately when a user completes enrollment or is deleted (`invalidateJwksCache()` called from `enrollment.js` and `adminUsers.js`).

**One key per user changes what a JWKS is.** A conventional OP rotates a handful of signing keys a few times a year; here the key set changes on every enrollment, re-enrollment and user deletion. A relying party that caches the whole JWKS for a fixed time will therefore fail a freshly enrolled user with *unknown kid* until its cache expires. Two mitigations exist on the provider side: `GET /jwks.json?kid=<kid>` returns just that key (non-standard, an extension of RFC 7517; the Carbonio connector uses it), and the `Cache-Control` on `/jwks.json` (`max-age=3600, stale-while-revalidate=86400`) should be read with that in mind. The robust fix is on the RP side: refetch the JWKS when a token names a `kid` the cache does not hold, as most JWT libraries do.

---

## Admin Network Restriction

`requireAdminNetwork` middleware restricts `/admin/*` to `ADMIN_ALLOWED_IPS` (comma-separated CIDRs or exact IPs). Default when not set: `127.0.0.1,::1` (localhost only). IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalised before comparison. A startup warning is logged when using the default.
