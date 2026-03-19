# Encedo OIDC Provider — Product Overview

> *Identity that no one can steal — not even the identity provider.*

---

## The problem with every other identity provider

Every major identity provider — whether cloud-hosted (Okta, Azure AD, Auth0) or self-hosted (Keycloak, Dex) — shares a fundamental architectural assumption: **the server holds the secrets**.

Your password is verified server-side. Your session is issued server-side. Your token is signed server-side. And that means: if the server is compromised, every user is compromised. If the provider operator turns malicious, they can impersonate any user. If the database leaks, identities leak with it.

This is the original sin of centralised identity — and enterprises have been quietly living with it for decades.

---

## A different architecture

Encedo OIDC Provider flips the model.

**The cryptographic authority lives in the user's hardware — not on the server.**

Each user owns an [Encedo HEM](https://encedo.com) hardware security module. Their Ed25519 private key is generated inside that hardware and never, under any circumstances, leaves it. When a user authenticates, their HSM physically signs the identity token. The provider server verifies the signature — but it cannot produce one.

```
Traditional IdP:                      Encedo OIDC Provider:

  User ──> Server                       User's HSM ──> Server
  "here's my password"                  "here's my signed token"
  Server decides: trust or not          Server verifies: valid or not

  Server CAN impersonate user.          Server CANNOT impersonate user.
  Database leak = identity theft.       Database leak = nothing sensitive.
```

---

## Zero-trust backend — by design

The Encedo OIDC Provider server builds the JWT payload (claims, expiry, audience) and sends the raw `signing_input` string to the user's browser. The browser forwards it to the HSM. The HSM signs it. The browser returns the signature. The server assembles the final token.

**This means:**
- The server controls what claims go into the token (standard OIDC compliance)
- The server verifies signatures — but cannot forge them
- No token can be issued without the user's physical hardware responding
- A compromised server can reject logins but cannot grant them

This is not a configuration option. It is a structural guarantee enforced by physics.

---

## A minimal, privacy-respecting database

Because the server never holds credentials, the database footprint is dramatically smaller than any traditional IdP.

**What the Encedo OIDC database stores per user:**

| Field | Value |
|-------|-------|
| `sub` | UUID — random, not derived from identity |
| `username` | Display name for lookup |
| `email` | For claims only |
| `hsm_url` | URL of user's HSM device |
| `pubkey` | 32-byte Ed25519 public key (not secret) |
| `hw_attested` | Whether key is hardware-backed |
| `hsm_crt` | Device X.509 certificate (public) |

**What it does NOT store:**
- Passwords
- Password hashes
- Session secrets
- Private keys
- MFA seeds or recovery codes
- Behavioural or device fingerprint data

A breach of the Encedo OIDC database exposes nothing that can be used to authenticate as a user. Public keys are public. Without the corresponding HSM, they are useless.

---

## Hardware attestation — proving the key is real

During enrollment, the user's HSM device provides a cryptographic attestation certificate (`genuine` + X.509 `crt`), validated in real-time against Encedo's attestation service. The provider records whether the key is genuinely hardware-backed.

This gives organisations a verifiable answer to the question: *"Is this key stored in certified hardware, or could it have been copied?"*

Organisations can enforce policy: only hardware-attested keys can access critical systems.

---

## Lightweight. Self-contained. Deployable anywhere.

The Encedo OIDC Provider is a single Node.js process with one dependency: Redis.

- No external databases
- No cloud connectivity required
- No licensing per-seat or per-request
- Binary footprint: tens of megabytes

It runs on a Raspberry Pi, on an air-gapped VM, on a Docker container in a hardened OT network, or on a cloud instance behind a load balancer. The deployment model is the operator's choice.

**Minimum production stack:**
```
[nginx] --> [encedo-oidc : Node.js] --> [Redis]
```

That's it.

---

## Built for OT and closed networks

Most enterprise identity systems assume internet connectivity. They phone home for licence checks, rely on cloud-hosted certificate authorities, or depend on SaaS components that cannot be deployed on-premises.

Encedo OIDC Provider has no such requirements.

**It runs fully offline.** The only external call in normal operation is the HSM URL — which is your device, on your network. Attestation validation is performed at enrollment time, not at every login.

This makes it suitable for:

- **OT / SCADA environments** — where network segmentation is mandatory and internet connectivity is prohibited by design
- **Industrial control systems** — where identity verification must not depend on an external SaaS vendor's availability
- **Air-gapped networks** — government, defence, critical infrastructure
- **Regulated environments** — where data residency requirements prohibit cloud-hosted IdPs

---

## Enterprise integration: SCADA, ICS, and beyond

Modern SCADA and ICS platforms increasingly support OpenID Connect for operator authentication. Encedo OIDC Provider speaks standard OIDC Core 1.0 — the same protocol used by every major enterprise application — making integration straightforward.

**Tested integrations:**
- Nextcloud (user_oidc app)
- Any OIDC-compliant application via standard discovery (`/.well-known/openid-configuration`)

**What OT operators gain:**

| Capability | Traditional IdP | Encedo OIDC |
|-----------|-----------------|-------------|
| Works without internet | No | **Yes** |
| Credentials breach-resistant | No | **Yes** |
| Operator cannot impersonate user | No | **Yes** |
| Hardware-bound identity | Optional (FIDO2) | **Always** |
| Deployable in air-gapped network | Rarely | **Yes** |
| Single-vendor SaaS dependency | Yes | **No** |
| Minimal database footprint | No | **Yes** |

---

## Security model summary

### What the provider guarantees

- **No token without hardware.** Every authentication requires a physical HSM to sign the token. No exceptions.
- **No impersonation by the operator.** The server cannot sign on behalf of a user, even with full database access.
- **No credential exposure.** The database contains only public keys, public certificates, and display data. Nothing that enables authentication without hardware.
- **Hardware provenance.** Keys are verified as hardware-generated at enrollment time. Attestation records are stored for audit.
- **Standard protocol.** Full OIDC Core 1.0 compliance — PKCE, JWKS, UserInfo, discovery, RP-initiated logout.

### Defence in depth

- Rate limiting on all authentication endpoints
- Short-lived sessions (pending session: 2 min, auth code: 60 s)
- Access tokens revocable per-user and on key rotation
- Security event log: dual-write to stderr and Redis ZSET (tamper-evident, SIEM-ready)
- Admin API restricted by IP allowlist, separate authentication, and rate limiting
- Content-Security-Policy enforced — JavaScript cannot be injected into the signing flow
- All HSM communication goes directly from user's browser to user's device — the server is never in the path of key material

### Threat model

| Threat | Traditional IdP | Encedo OIDC |
|--------|-----------------|-------------|
| Server compromise → credential theft | **Critical** | Minimal — no credentials stored |
| Server compromise → token forgery | **Critical** | Not possible — server cannot sign |
| Database breach → identity theft | **Critical** | No impact — public data only |
| Insider threat (operator) | **Critical** | Not possible — no signing authority |
| HSM device theft | Low | Mitigated — passphrase or mobile approval required |
| Replay attack | Standard mitigations | One-time codes, short TTLs, PKCE |

---

## Who is it for?

- **OT/ICS operators** who need standards-based SSO in environments where cloud identity is not an option
- **Security-conscious enterprises** who want to eliminate the "IdP as single point of failure" risk
- **Regulated industries** (energy, water, manufacturing, defence) with strict data residency and air-gap requirements
- **Development teams** building systems where the identity provider should be structurally incapable of impersonating users

---

## Summary

Encedo OIDC Provider is not a faster or cheaper version of what already exists. It is a different category of product: an identity provider where **the provider itself is not a trusted party in the credential chain**.

Authentication happens because the user's hardware says so. The provider's job is to verify, record, and relay — not to hold, store, or grant.

For environments where identity is a matter of physical and operational security — not just software policy — this distinction is everything.

---

*Encedo OIDC Provider is open-source. Runs on-premises. No SaaS. No phoning home. No per-seat licensing.*
