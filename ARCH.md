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
|  Admin API       ->  src/routes/adminUsers.js|
|                       src/routes/adminClients|
|                                              |
|  Middleware: auth, rateLimit, validate,      |
|              errorHandler                    |
|  Services:   redis, securityLog, attestation |
+----------+-----------------------------------+
           |
           +-- Redis (sole persistence layer)
           |
           +-- api.encedo.com  (HSM attestation)

Browser calls HSM directly (Encedo HEM SDK)
```

The browser (Trusted App, `signin.js`) communicates with the HSM directly over HTTPS. The backend **never** sees the private key — it only verifies Ed25519 signatures using the public key stored in Redis.

---

## Login Flow (detailed)

```
 Browser                     Backend                    HSM
    |                            |                       |
    |-- GET /authorize --------->|                       |
    |<-- signin.html ------------|                       |
    |                            |                       |
    |-- POST /api/checkin ------------------------------>|
    |-- POST /api/keymgmt/search (EXTAID)  ------------->|
    |-- POST /api/keymgmt/search (ETSOIDC) ------------->|
    |                            |                       |
    |-- POST /authorize/login -->|                       |
    |      {sub, client_id,      |                       |
    |       code_challenge}      |                       |
    |                            |-- build signing_input |
    |                            |-- store pending:{sid} |
    |<-- {session_id,            |                       |
    |     signing_input} --------|                       |
    |                            |                       |
    |-- POST /api/sign --------------------------------->|
    |<-- signature --------------------------------------|
    |                            |                       |
    |-- POST /authorize/confirm->|                       |
    |      {session_id,          |                       |
    |       signature}           |-- verify Ed25519      |
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
- Backend stores as **hex** (32 raw bytes)
- SPKI DER prefix `302a300506032b6570032100` is prepended at verification time

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
searchKeys(token, '^' + btoa('ETSOIDC'))  // pattern prefix match
```
This links HSM keys to user subs. Mobile app detection uses prefix `^RVhUQUlE` (= `btoa('EXTAID')`).

### EdDSA signing in HEM SDK
```javascript
// msg sent to HSM = base64 of UTF-8 bytes of signing_input
body.msg = toB64(strToBytes(signing_input));
// HSM returns standard base64 signature → convert to base64url for JWT
```

### Enrollment challenge-response
`GET /enrollment/validate` issues a 32-byte random challenge. The frontend signs it with the newly created HSM key and sends `signature` to `/enrollment/submit`. The backend verifies the signature using the submitted pubkey. This proves the enrolling party actually possesses the private key.

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
    |                            |-- validate timestamp  |
    |                            |   (not future, <15s)  |
    |                            |-- store hw_attested,  |
    |                            |   hsm_crt in Redis    |
    |<-- {ok, hw_attested} ------|                       |
```

`genuine` is a device-signed blob. `crt` is the X.509 device certificate (contains SKID). Both stored in `user:{sub}` for audit purposes.

---

## File Structure

```
encedo-oidc/
├── src/
│   ├── app.js                    Entry point: Express setup, middleware, routing
│   ├── routes/
│   │   ├── oidc.js               All OIDC endpoints + JWKS cache + discovery
│   │   ├── enrollment.js         HSM key enrollment (validate + submit)
│   │   ├── adminUsers.js         CRUD /admin/users + audit log
│   │   └── adminClients.js       CRUD /admin/clients
│   ├── middleware/
│   │   ├── auth.js               requireAdminAuth + requireAdminNetwork
│   │   ├── rateLimit.js          Redis-backed per-key sliding window
│   │   ├── validate.js           Input validators (email, url, pkce, sig, ...)
│   │   └── errorHandler.js       Central Express error handler
│   └── services/
│       ├── redis.js              Singleton Redis client (node-redis v4)
│       ├── securityLog.js        Security event log (Redis ZSET + stderr)
│       └── attestation.js        HSM attestation validation via api.encedo.com
├── signin.js                     Trusted App logic (served as /signin.js)
├── signin.html                   Trusted App shell (served at /authorize)
├── enrollment.js                 Enrollment flow logic
├── enrollment.html               Enrollment shell
├── admin-panel.js                Admin panel logic
├── admin-panel.html              Admin panel shell
├── hem-sdk.js                    Encedo HEM JavaScript SDK
└── rp-server.mjs                 Test Relying Party (port 9876)
```

---

## Redis Schema

```
user:{sub}               Hash
  sub                    UUID
  username               string (indexed in username_index)
  name                   string
  email                  string (lowercase)
  hsm_url                HTTPS URL of HSM
  kid                    hex — SHA1(pubkey)[:16 bytes]
  pubkey                 hex — 32-byte raw Ed25519 public key
  hw_attested            'true' | 'false'
  hsm_crt                PEM X.509 device certificate (from enrollment)
  clients                JSON array of client_id strings
  enrollment_token       base64url — present until enrollment completes
  enrolled_at            ISO 8601
  created_at             ISO 8601
  updated_at             ISO 8601

username_index           Hash  { username → sub }   (O(1) lookup)

users                    Set   { sub, sub, ... }

client:{client_id}       Hash
  client_id, name
  client_secret          stored in plain text — use strong random value
  redirect_uris          JSON array
  scopes                 JSON array
  pkce                   'true' | 'false'
  id_token_ttl           seconds (integer string)
  access_token_ttl       seconds (integer string)
  created_at             ISO 8601

pending:{session_id}     JSON  TTL 120s
  sub, kid, client_id, scope, nonce
  redirect_uri, code_challenge, code_challenge_method
  signing_input, state, auth_time

code:{code}              JSON  TTL 60s
  sub, client_id, scope, nonce
  code_challenge, redirect_uri, id_token

access:{token}           JSON  TTL = access_token_ttl
  sub, client_id, scope

user_tokens:{sub}        Set   { access:{token}, ... }  TTL = max(token TTL)

enrollment:{token}       JSON  TTL 24h → 30 min after validate
  sub, username, challenge

enroll_lock:{sub}        String TTL 30s  (Redis NX lock, one enrollment at a time)

security:log             ZSet  score=ms_timestamp  value=JSON event
                               capped at 20 000 entries

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
| `admin.auth.fail` | Wrong ADMIN_SECRET |
| `admin.user.create` | User created |
| `admin.user.patch` | User updated |
| `admin.user.delete` | User deleted |
| `admin.client.create` | Client created |
| `admin.client.patch` | Client updated |
| `admin.client.delete` | Client deleted |
| `admin.client.rotate_secret` | Client secret rotated |

Events are written to **stderr** (synchronous, captured by journald/Docker) and to the Redis ZSET (accessible via admin panel audit log).

---

## Rate Limits

Applied per endpoint via `src/middleware/rateLimit.js` (sliding window, Redis-backed):

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /authorize/login` | 20 | 60s | `client_id` |
| `POST /authorize/confirm` | 10 | 60s | `session_id` |
| `POST /token` | 20 | 60s | `client_id` |
| `GET /userinfo` | 60 | 60s | `Bearer token` |
| `GET /logout` | 20 | 60s | IP |
| `GET /enrollment/validate` | 10 | 60s | `token` |
| `POST /enrollment/submit` | 5 | 60s | `token` |
| `POST /admin/*` | 60 | 60s | IP |

Additionally, nginx `limit_req` should be configured upstream (see README) to rate-limit `GET /authorize` and provide a second line of defence.

---

## JWKS Cache

`GET /jwks.json` builds the key list from all users in Redis. To avoid an O(n) Redis read on every OIDC discovery request, the result is cached in-process for 60 seconds. The cache is invalidated immediately when a user completes enrollment (`invalidateJwksCache()` called from `enrollment.js`).

---

## Admin Network Restriction

`requireAdminNetwork` middleware restricts `/admin/*` to `ADMIN_ALLOWED_IPS` (comma-separated CIDRs or exact IPs). Default when not set: `127.0.0.1,::1` (localhost only). IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalised before comparison. A startup warning is logged when using the default.
