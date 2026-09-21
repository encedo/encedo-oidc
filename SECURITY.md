# Security Model — Encedo OIDC Provider

## Threat Model

The system protects against:
- Credential theft (no passwords stored — HSM holds private keys)
- Token forgery (signing requires physical HSM access — Ed25519 or ECDSA, the key never leaves the device)
- Replay attacks (one-time codes, challenge-response, session TTLs)
- Admin API abuse (network isolation + strong secret + rate limiting)
- Fake HSM detection — hardware attestation (via api.encedo.com) is **recorded** as `hw_attested`
  for audit and downstream trust decisions, but is **not** enforced at enrollment (advisory signal;
  see [Hardware attestation](#hardware-attestation)).

Primary threat actor: attacker with network access but **without** physical access to the HSM device.

---

## Core Security Properties

### Private key never leaves HSM
The private key (Ed25519, or ECDSA on P-256/P-384/P-521 — chosen per user at enrollment) is generated inside Encedo hardware and is never exported. JWT signing requires physical confirmation (mobile push or passphrase), or a still-valid single sign-on token in the same browser (see *Single sign-on session*). The backend only sees and stores the **public key**.

### Backend controls all JWT claims
The backend builds `signing_input = base64url(header).base64url(payload)`. The browser submits this to the HSM for signing. The browser cannot alter the payload — the backend assembles the final JWT.

### Public key always from Redis
Signature verification uses the public key (and key type) from `user:{sub}` in Redis — never from the request. The frontend cannot substitute a different key.

### The ID Token is signed by the *user's* key — what that means for a Relying Party
There is no provider signing key. `jwks.json` publishes the enrolled users' public keys, and every ID Token carries the signature the user's HSM produced over the payload the server built. That is the point of the design (the server cannot forge a login), but it moves one trust boundary that OIDC Core takes for granted: a JWT that verifies against `jwks_uri` is proof that **the user's key signed it**, not that **the provider issued it**. A user can sign any payload they like offline — their own `sub`, but someone else's `email`, `email_verified: true`, any `aud`, an `exp` years away — and it will verify against the published key.

Consequences an RP must respect:

- **Trust an ID Token only as the response of `POST /token`** (the code flow, server-to-server, with client authentication). That response is the provider's assertion; the signature inside it is the user's.
- **Never accept an ID Token from another channel** as a bearer credential to an API, as a "login with JWT" input, or as an `id_token_hint` that decides anything security-relevant. `jwks_uri` verification alone is not authorisation here.
- Claims about identity that other systems key on (`email`, `preferred_username`) are only trustworthy in the `/token` response — the Carbonio connector, which maps `email` to a mailbox, must take them from there and nowhere else.
- `at_hash` / `c_hash` cannot be issued: the token is signed before the access token exists.

Signing algorithms are those the HSM supports: `EdDSA` (Ed25519) and `ES256/ES384/ES512`. `RS256`, which OIDC Core §15.1 lists as mandatory for an OP, is **not** available (no RSA keys in the HSM); an RP library hard-wired to `RS256` must be configured for `EdDSA` or an `ES*` algorithm.

### kid is session-locked
`POST /authorize/login` stores the user's current `kid` in the pending session. `POST /authorize/confirm` rejects any mismatch — prevents key substitution between the two calls.

---

## Authentication Controls

### Client authentication at `/token` (RFC 6749 §3.2.1)
Every client is confidential unless registered with `public: true`. A confidential client must present its `client_secret` on every token request (`client_secret_basic` or `client_secret_post`) — PKCE never substitutes for it, it is verified in addition whenever the authorization request carried a `code_challenge`. A public client (SPA / native app, `token_endpoint_auth_method=none`) has no secret; it is bound to its code by PKCE alone, which the authorization endpoint makes mandatory for it. `invalid_client` is answered with 401 and, for HTTP Basic, a matching `WWW-Authenticate`. Token responses carry `Cache-Control: no-store`.

### PKCE S256 (RFC 7636)
Required per client (configurable, default on; always on for public clients). Protects against authorization code interception. Code verifier 43–128 characters, challenge method must be `S256` — a `code_challenge` without `code_challenge_method=S256` is refused at the authorization endpoint.

### Single sign-on session (HEM token in the browser)
After an authorization the sign-in page may keep the HEM-issued token for the user's key (`keymgmt:use:<kid>`) in `localStorage` of the provider origin and reuse it to have the HEM sign further ID Tokens without a new phone/passphrase confirmation. Properties:

- The token is a bearer credential to sign with that key until it expires. It is worth nothing without network access to the HEM, and it **never reaches the server** — the page reports only the authorization time (`sso_iat`); a server holding the token could sign without the device, which would break the core guarantee.
- Lifetime is decided by the device/user (the page suggests `SSO_SUGGEST_SECONDS`, default 8 h; the user may change it on the phone). The server refuses a session older than `SSO_MAX_SECONDS` (8 h) regardless.
- Policy is a conjunction: `SSO_ENABLED`, `client.sso`, `user.sso`, the browser tick, and the RP's `prompt`/`max_age`. Any refusal turns the attempt into a normal interactive sign-in; the reason is reported to the page.
- `auth_time` in the ID Token is the original HEM authorization; `amr` distinguishes `["hwk"]` from `["hwk","sso"]`, so an RP can require freshness on its own.
- Ending a session: token expiry, `/logout` on the provider (its page, `logout.html` + `logout.js`, asks whether to sign out of Encedo as well when the browser still holds a session for the signed-out user — RP-Initiated Logout 1.0 §2 — and clears the entries only on “Yes”; with no session kept it redirects at once), “Forget all sessions in this browser”, or the device refusing the token (unplugged/rebooted — the HEM issues no long-lived state to the phone app).
- Exposure: an XSS on the provider origin could read the token — the same threat as a session cookie without HttpOnly; the CSP (no inline script, no inline handlers) is the control. A stolen token is usable only while the HEM stays reachable to the thief.

### Timing-safe comparisons
`client_secret` and `ADMIN_SECRET` are compared using `crypto.timingSafeEqual`. Prevents secret length/value leakage via timing side-channel.

### One-time codes
Authorization codes (`code:{code}`) have a 60-second TTL and are deleted on first use (`getDel`). Enrollment tokens are similarly one-time-use.

### Challenge-response at enrollment
`/enrollment/validate` issues a 32-byte random challenge. The enrolling party must sign it with the new key and submit the signature to `/enrollment/submit`. Backend verifies Ed25519 — proves possession of the corresponding private key. A public-only key or a guessed key cannot pass enrollment.

### Hardware attestation
At enrollment, the frontend fetches `genuine` + `crt` from `GET {hsm_url}/api/system/config/attestation` and forwards them to `POST api.encedo.com/attest`. The backend (`src/services/attestation.js`) treats `result === 'ok'` from Encedo's attestation service as the outcome; freshness/replay checks are delegated to `api.encedo.com` (local timestamp validation was removed to avoid clock-skew false negatives).

The outcome is stored as `hw_attested` (`'true'`/`'false'`) in `user:{sub}`, and the X.509 device certificate (`hsm_crt`) is stored for audit.

**Enforcement:** enrollment is **not** blocked when attestation fails — a failed/absent attestation is logged and stored as `hw_attested='false'`, and enrollment proceeds (`src/routes/enrollment.js`). This is a deliberate product decision: `hw_attested` is an **advisory** signal for audit and downstream trust, not a gate. Consumers that require a genuine device must check `hw_attested` themselves. To make it a hard gate, block enrollment when `hw_attested !== 'true'`.

---

## Input Validation

All inputs are validated in `src/middleware/validate.js`:

| Field | Rule |
|-------|------|
| `email` | RFC 5322 simplified, max 320 chars, lowercased |
| `username` | `[a-zA-Z0-9._@-]`, 2–64 chars |
| `name` (user), `name` (client) | max 128 chars, no control characters (they reach mail headers and logs) |
| `hsm_url` | HTTPS only (localhost exempt), no credentials in URL |
| `code_challenge` | Base64url, 43–128 chars (RFC 7636); `code_challenge_method` must be `S256` |
| `code_verifier` | Unreserved chars, 43–128 chars (RFC 7636) |
| `signature` | Base64url, 64–200 chars (Ed25519/P-256 = 64 bytes, P-384 = 96, P-521 = 132) |
| `pubkey` | Hex, length per key type (Ed25519 64, P-256 66, P-384 98, P-521 134 — compressed EC points) |
| `kid` | Verified server-side: must equal `SHA1(pubkey)[:16]` |
| OIDC parameters | Single-valued: a repeated query/form key is `invalid_request` |
| Body size | 32 KB limit on all endpoints |

---

## Rate Limiting

Redis-backed sliding window per endpoint (see `src/middleware/rateLimit.js`):

| Endpoint | Max | Window | Key |
|----------|-----|--------|-----|
| `POST /authorize/login` | 20 + 40 | 60 s | client_id, plus an IP backstop |
| `POST /authorize/confirm` | 10 | 60 s | IP |
| `POST /token` | 20 | 60 s | IP |
| `GET`/`POST /logout` | 20 | 60 s | IP |
| `POST /enrollment/validate` | 10 + 30 | 60 s | enrollment token, plus an IP backstop |
| `POST /enrollment/submit` | 5 + 20 | 60 s | enrollment token, plus an IP backstop |
| `POST /verify-email/confirm` | 20 | 60 s | IP |
| `/admin/*` (authenticated) | 60 | 60 s | IP |
| `/admin/*` failed authentications | 10 | 60 s | IP — then every admin call from that IP is 429 until the window passes |

`/userinfo` is not rate-limited at application level. The limiter is **fail-open**: if Redis cannot be reached the request goes through (Redis is also the session store, so little works in that state anyway, but authentication is never blocked by the limiter itself). Counters are created with their expiry in one command (`SET NX EX` + `INCR`), so a counter can never exist without a TTL. The audit entry for a limit hit hashes any key that is not an IP or UUID — an enrollment token used as the key never lands in the log. `GET /authorize` is not rate-limited at application level — nginx `limit_req` should handle it upstream. All per-IP limits and the admin allow-list need `TRUST_PROXY=1` behind a reverse proxy; the server warns once when it sees `X-Forwarded-For` without it.

The following endpoints are rate-limited **at nginx level only** (see README nginx config):

| Endpoint | Zone | Limit |
|----------|------|-------|
| `POST /signup/prefill`, `POST /signup-client/prefill` | `oidc_signup` | 20 r/m, burst 5 |
| `POST /signup/register`, `POST /signup-client/register` | `oidc_login` | 5 r/m, burst 2 |
| `POST /admin/invite`, `POST /admin/invite-client` | `oidc_login` | 5 r/m, burst 2 |

---

## Admin API Security

- **Network isolation:** `ADMIN_ALLOWED_IPS` restricts access by IP/CIDR. Default when unset: `127.0.0.1,::1`. IPv4-mapped IPv6 (`::ffff:x.x.x.x`) normalised automatically. Production must set this to a management network or use nginx `allow`/`deny`.
- **Authentication:** `Authorization: Bearer <ADMIN_SECRET>` checked with `timingSafeEqual`.
- **Rate limit:** 60 req/min per IP for authenticated calls; 10 failed authentications per minute per IP lock that IP out of the admin API until the window passes.
- **Startup warning:** Server logs a warning when `ADMIN_ALLOWED_IPS` is not set or `ADMIN_SECRET` uses the default.

---

## Security Headers

Set on all responses via `src/app.js`:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'`; `connect-src 'self' https://*.ence.do https://api.encedo.com` (+ `CSP_CONNECT_EXTRA`); `script-src 'self'`; `style-src 'self' <sha256 hashes> https://fonts.googleapis.com`; `style-src-attr 'unsafe-inline'`; `font-src 'self' https://fonts.gstatic.com`; `img-src 'self' data:`; `frame-ancestors 'none'`; `base-uri 'self'`; `form-action 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (production only) |

JS is extracted to external files (`signin.js`, `enrollment.js`, `admin-panel.js`, `signup.js`, `signup-client.js`, `verify-email.js`, `logout.js`, `index.js`, `landing.js`, shared `hsm-common.js`) — no inline `<script>` blocks and no inline `on*=` handlers: `script-src 'self'` is enforced without `'unsafe-inline'` and without a permissive `script-src-attr`, so markup injected into the page can never execute. Clicks are dispatched through `data-action` attributes and a delegated listener. CSP style hashes cover exact `<style>` block content in HTML files (9 files: signin, enrollment, admin-panel, index, landing, signup, signup-client, verify-email, logout); `node update-csp-hashes.js` regenerates them.

The admin secret is kept in `sessionStorage` (per tab, gone when the tab closes) and can be dropped with the “Forget secret” button; the API base URL alone is remembered in `localStorage`.

---

## Container

The Docker image (`node:22-alpine`) runs the app as the unprivileged `node` user. The copied tree is made world-readable at build time (`chmod -R a+rX /app`), so the build host's umask cannot produce an image whose files `node` cannot open — a checkout pulled with umask 077 did exactly that once and left every container in a restart loop. The image carries no secrets: everything sensitive comes from the tenant's `.env` (mode 600) at run time. A `HEALTHCHECK` polls `/health`, which answers 503 when Redis is unreachable, so `docker ps` shows a dead datastore as an unhealthy container. Each tenant's Redis lives on a private Docker network with `requirepass`; only that tenant's OIDC container can reach it.

---

## Token Revocation

| Token type | Revocation |
|-----------|------------|
| Authorization code | One-time use (`getDel`), 60 s TTL |
| Access token | Stored in Redis (`access:{token}`), deleted explicitly on logout or user delete |
| id_token | JWT — not revocable by design (OIDC spec). TTL configurable per client. JWKS key is removed the moment the user is deleted (cache invalidated), invalidating future RP cache refreshes. |

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

`/token` requires the `client_secret` for confidential clients and PKCE for public ones (see *Client authentication*). CORS `*` on `/token` is standard OIDC practice — the authorization code is single-use and bound to `redirect_uri`, limiting the attack surface.

---

## Enrollment Security

- Enrollment token: 32 random bytes, base64url-encoded (256-bit entropy), 24 h TTL
- Token is delivered out-of-band (email/admin channel) — not in server access logs: the link carries it in the URL fragment and every API call (`/enrollment/validate`, `/signup/prefill`, `/signup-client/prefill`, `/enrollment/submit`) sends it in a POST body, never in a query string
- Token consumed atomically (compare-and-delete against the validated session) **after** the signature, key type and duplicate-key checks pass — a rejected attempt leaves the link usable, a completed one cannot be replayed
- Concurrent enrollment for the same user blocked with Redis NX lock (`enroll_lock:{sub}`, 30 s TTL); the challenge is set with compare-and-set so two first calls to `/validate` share one challenge
- Duplicate public key rejection: checked across all users before commit
- Token invalidated on user delete: no orphaned enrollment tokens

### Invite Flow Security

- Invite tokens: `randomBytes(32).toString('base64url')` — 43 chars, 256-bit entropy, 24 h TTL (base64url keeps invite URLs short enough to wrap cleanly in email)
- Token delivered via admin panel as a URL fragment (`#token=...`) — not logged by server
- Token format validated with `TOKEN_RE = /^([a-f0-9]{64}|[A-Za-z0-9_-]{43})$/` before any Redis call (accepts current base64url and legacy 64-hex tokens during their 24 h TTL)
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
| ID Token signed by the user's key, not a provider key | Design | See *The ID Token is signed by the user's key*: RPs must trust it only as the `/token` response, never from another channel |
| No `RS256` | Design | HSM has no RSA; `EdDSA` / `ES256` / `ES384` / `ES512` only — configure the RP accordingly |
| `post_logout_redirect_uri` by origin for clients without `post_logout_redirect_uris` | Low | Legacy fallback, logged once per client; register the logout URL to get exact matching |
| Redis of every tenant on the shared `oidc-net` without a password | Medium | Fixed in `tenants/docker-compose.yml` (per-tenant `internal` network + `requirepass`); deployments created earlier must run the one-time migration in README §*Isolate each tenant's Redis* |
| Redis without TLS | Ops | Use `rediss://` URL in production; run Redis on loopback or VPN-protected network |
| SHA-1 for kid derivation | Accepted | Matches HSM convention; second-preimage attack (~2¹⁶⁰) infeasible; collision is cosmetic, not an auth bypass |
