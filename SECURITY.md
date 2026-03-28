# Security Model — Encedo OIDC Provider

## Threat Model

The system protects against:
- Credential theft (no passwords stored — HSM holds private keys)
- Token forgery (Ed25519 signing requires physical HSM access)
- Replay attacks (one-time codes, challenge-response, session TTLs)
- Admin API abuse (network isolation + strong secret + rate limiting)
- Fake HSM enrollment (hardware attestation via api.encedo.com)

Primary threat actor: attacker with network access but **without** physical access to the HSM device.

---

## Core Security Properties

### Private key never leaves HSM
The Ed25519 private key is generated inside Encedo hardware and is never exported. JWT signing requires physical confirmation (mobile push or passphrase). The backend only sees and stores the 32-byte **public key**.

### Backend controls all JWT claims
The backend builds `signing_input = base64url(header).base64url(payload)`. The browser submits this to the HSM for signing. The browser cannot alter the payload — the backend assembles the final JWT.

### Public key always from Redis
Ed25519 signature verification uses the public key from `user:{sub}.pubkey` in Redis — never from the request. The frontend cannot substitute a different key.

### kid is session-locked
`POST /authorize/login` stores the user's current `kid` in the pending session. `POST /authorize/confirm` rejects any mismatch — prevents key substitution between the two calls.

---

## Authentication Controls

### PKCE S256 (RFC 7636)
Required per client (configurable, default on). Protects against authorization code interception. Code verifier 43–128 characters, challenge method must be `S256`.

### Timing-safe comparisons
`client_secret` and `ADMIN_SECRET` are compared using `crypto.timingSafeEqual`. Prevents secret length/value leakage via timing side-channel.

### One-time codes
Authorization codes (`code:{code}`) have a 60-second TTL and are deleted on first use (`getDel`). Enrollment tokens are similarly one-time-use.

### Challenge-response at enrollment
`/enrollment/validate` issues a 32-byte random challenge. The enrolling party must sign it with the new key and submit the signature to `/enrollment/submit`. Backend verifies Ed25519 — proves possession of the corresponding private key. A public-only key or a guessed key cannot pass enrollment.

### Hardware attestation
At enrollment, the frontend fetches `genuine` + `crt` from `GET {hsm_url}/api/system/config/attestation` and forwards them to `POST api.encedo.com/attest`. The backend validates:
- `result === 'ok'` from Encedo's attestation service
- `checks.genuine_ok`, `crt_trusted`, `pairing_ok`
- Timestamp: not in the future (±5 s skew), not older than 15 seconds (replay prevention; clocks synchronised via `/checkin`)

Result stored as `hw_attested` in `user:{sub}`. The X.509 device certificate (`hsm_crt`) is stored for audit.

---

## Input Validation

All inputs are validated in `src/middleware/validate.js`:

| Field | Rule |
|-------|------|
| `email` | RFC 5322 simplified, max 320 chars, lowercased |
| `username` | `[a-zA-Z0-9._@-]`, 2–64 chars |
| `hsm_url` | HTTPS only (localhost exempt), no credentials in URL |
| `code_challenge` | Base64url, 43–128 chars (RFC 7636) |
| `code_verifier` | Unreserved chars, 43–128 chars (RFC 7636) |
| `signature` | Base64url, 86–88 chars (Ed25519 = 64 bytes) |
| `pubkey` | 64 hex chars (32-byte raw Ed25519) |
| `kid` | Verified server-side: must equal `SHA1(pubkey)[:16]` |
| Body size | 32 KB limit on all endpoints |

---

## Rate Limiting

Redis-backed sliding window per endpoint (see `src/middleware/rateLimit.js`):

| Endpoint | Max | Window | Key |
|----------|-----|--------|-----|
| `POST /authorize/login` | 20 | 60 s | client_id |
| `POST /authorize/confirm` | 10 | 60 s | session_id |
| `POST /token` | 20 | 60 s | client_id |
| `GET /userinfo` | 60 | 60 s | access token |
| `GET /logout` | 20 | 60 s | IP |
| `GET /enrollment/validate` | 10 | 60 s | enrollment token |
| `POST /enrollment/submit` | 5 | 60 s | enrollment token |
| `/admin/*` | 60 | 60 s | IP |

Rate limiter is fail-closed by design: Redis outage means the OIDC service cannot function anyway (all session state is in Redis). `GET /authorize` is not rate-limited at application level — nginx `limit_req` should handle it upstream.

The following endpoints are rate-limited **at nginx level only** (see README nginx config):

| Endpoint | Zone | Limit |
|----------|------|-------|
| `GET /signup/prefill`, `GET /signup-client/prefill` | `oidc_signup` | 20 r/m, burst 5 |
| `POST /signup/register`, `POST /signup-client/register` | `oidc_login` | 5 r/m, burst 2 |
| `POST /admin/invite`, `POST /admin/invite-client` | `oidc_login` | 5 r/m, burst 2 |

---

## Admin API Security

- **Network isolation:** `ADMIN_ALLOWED_IPS` restricts access by IP/CIDR. Default when unset: `127.0.0.1,::1`. IPv4-mapped IPv6 (`::ffff:x.x.x.x`) normalised automatically. Production must set this to a management network or use nginx `allow`/`deny`.
- **Authentication:** `Authorization: Bearer <ADMIN_SECRET>` checked with `timingSafeEqual`.
- **Rate limit:** 60 req/min per IP.
- **Startup warning:** Server logs a warning when `ADMIN_ALLOWED_IPS` is not set or `ADMIN_SECRET` uses the default.

---

## Security Headers

Set on all responses via `src/app.js`:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'`; `connect-src 'self' https://*.ence.do https://api.encedo.com`; `script-src 'self'`; `frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (production only) |

JS is extracted to external files (`signin.js`, `enrollment.js`, `admin-panel.js`, `signup.js`, `signup-client.js`, `index.js`) — no inline `<script>` blocks. `script-src 'self'` is enforced without `'unsafe-inline'`. CSP style hashes cover exact `<style>` block content in HTML files (6 files: signin, enrollment, admin-panel, index, signup, signup-client).

---

## Token Revocation

| Token type | Revocation |
|-----------|------------|
| Authorization code | One-time use (`getDel`), 60 s TTL |
| Access token | Stored in Redis (`access:{token}`), deleted explicitly on logout or user delete |
| id_token | JWT — not revocable by design (OIDC spec). TTL configurable per client. JWKS key is removed when user is deleted, invalidating future RP cache refreshes. |

Active access tokens are tracked per user in `user_tokens:{sub}` and bulk-revoked on user deletion or re-enrollment.

---

## Security Logging

Every security-relevant event is written to:
1. **stderr** — synchronous, captured by journald / Docker logging drivers, survives Redis outage
2. **Redis ZSET** `security:log` — capped at 20 000 entries, accessible via admin panel audit log
3. **Redis Pub/Sub** `security:events` — for real-time consumers / SIEM integration

Logged events include: login attempts, signature verification results, token issuance, enrollment outcomes, admin operations, and logout events. PII (sub, email) is included in security log entries (necessary for audit) but excluded from operational `console.log` output.

---

## CORS Policy

| Endpoint group | CORS |
|----------------|------|
| `/jwks.json`, `/.well-known/*` | `Access-Control-Allow-Origin: *` |
| `/token`, `/userinfo` | `Access-Control-Allow-Origin: *` |
| `/authorize`, `/enrollment`, `/admin/*` | No CORS headers |

`/token` requires PKCE or `client_secret`. CORS `*` on `/token` is standard OIDC practice — the authorization code is single-use and bound to `redirect_uri`, limiting the attack surface.

---

## Enrollment Security

- Enrollment token: 32 random bytes, base64url-encoded (256-bit entropy), 24 h TTL
- Token is delivered out-of-band (email/admin channel) — not in server access logs (URL fragment)
- Token consumed atomically with `getDel` — cannot be reused
- Concurrent enrollment for the same user blocked with Redis NX lock (`enroll_lock:{sub}`, 30 s TTL)
- Duplicate public key rejection: checked across all users before commit
- Token invalidated on user delete: no orphaned enrollment tokens

### Invite Flow Security

- Invite tokens: `randomBytes(32).toString('hex')` — 64 hex chars, 256-bit entropy, 24 h TTL
- Token delivered via admin panel as a URL fragment (`#token=...`) — not logged by server
- Token format validated with `TOKEN_RE = /^[a-f0-9]{64}$/` before any Redis call
- Inputs validated **before** token consumption — a validation error does not burn the invite
- Token consumed atomically with `getDel` — race-safe, single use
- User invite (`invite:{token}`) tied to a specific `client_id` — user is enrolled for that client
- Client invite (`client-invite:{token}`) creates a new OIDC client with credentials shown once

---

## Known Limitations and Accepted Risks

| Item | Severity | Notes |
|------|----------|-------|
| `GET /authorize` not rate-limited at app level | Medium | Delegated to nginx `limit_req` (see README) |
| id_token not revocable (JWT) | Low | Standard OIDC limitation; configure short `id_token_ttl` per client; JWKS key removed on user delete |
| Admin panel has no browser logout | Low | Bearer token in browser memory; no persistent session |
| Redis without TLS | Ops | Use `rediss://` URL in production; run Redis on loopback or VPN-protected network |
| SHA-1 for kid derivation | Accepted | Matches HSM convention; second-preimage attack (~2¹⁶⁰) infeasible; collision is cosmetic, not an auth bypass |
