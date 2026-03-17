# Encedo OIDC Provider

HSM-anchored OpenID Connect Identity Provider.
Klucze prywatne **nigdy nie opuszczają HSM**. Każde podpisanie tokena wymaga fizycznego potwierdzenia na urządzeniu mobilnym lub podania PIN-u.

---

## Architektura

```
Browser / RP
    │
    ▼
┌─────────────────────────────────────────────┐
│  Encedo OIDC Provider  (Node.js / Express)  │
│                                             │
│  GET  /authorize          → signin.html│
│  POST /authorize/login    → session w Redis │
│  POST /authorize/confirm  → weryfikacja sig │
│  POST /token              → PKCE S256       │
│  GET  /userinfo           → Bearer token    │
│  GET  /jwks.json                            │
│  GET  /.well-known/openid-configuration     │
└──────────────────┬──────────────────────────┘
                   │ Redis (jedyna baza)
                   ▼
┌─────────────────────────────────────────────┐
│  Trusted App  (SPA w przeglądarce)          │
│                                             │
│  1. GET {hsm_url}/api/keymgmt/search        │ ← wykrycie trybu
│  2. GET {hsm_url}/api/keymgmt/search        │ ← klucze OIDC
│  3. POST {hsm_url}/api/authorize-key-op     │ ← mobilka lub PIN
│  4. POST {hsm_url}/api/sign                 │ ← podpisanie JWT
└──────────────────┬──────────────────────────┘
                   │ HTTPS
                   ▼
         Encedo HEM (HSM hardware)
```

### Kluczowe właściwości

- Klucze Ed25519 w HSM — backend weryfikuje podpis, nigdy nie widzi klucza prywatnego
- `signing_input = base64url(header).base64url(payload)` — backend buduje JWT, frontend tylko podpisuje
- PKCE S256 — zabezpieczenie przed przechwyceniem kodu autoryzacyjnego
- Redis — jedyna warstwa persystencji (użytkownicy, klienci, sesje, tokeny)

---

## Quick Start

```bash
# 1. Zależności
npm install

# 2. Konfiguracja
cp .env.example .env
# edytuj .env — zmień ADMIN_SECRET, ustaw ISSUER

# 3. Redis
sudo systemctl start redis

# 4. Dev (hot reload)
npm run dev

# 5. Produkcja
npm start
```

### Zmienne środowiskowe (`.env`)

```
PORT=3000
ISSUER=http://localhost:3000
ADMIN_SECRET=change-me-please
REDIS_URL=redis://localhost:6379
NODE_ENV=development
```

---

## Struktura projektu

```
encedo-oidc/
├── src/
│   ├── app.js                    # Entry point, Express, routing
│   ├── routes/
│   │   ├── oidc.js               # Wszystkie endpointy OIDC
│   │   ├── enrollment.js         # Rejestracja kluczy HSM
│   │   ├── adminUsers.js         # CRUD /admin/users
│   │   └── adminClients.js       # CRUD /admin/clients
│   ├── middleware/
│   │   ├── auth.js               # Bearer guard (Admin API)
│   │   └── errorHandler.js       # Centralny handler błędów
│   └── services/
│       └── redis.js              # Singleton Redis client
├── signin.html              # Trusted App SPA (przeglądarka)
├── enrollment.html               # Ekran rejestracji klucza HSM
├── admin-panel.html              # Panel zarządzania
├── hem-sdk.js                    # Encedo HEM JavaScript SDK
├── rp-server.mjs                 # Testowy Relying Party (port 9876)
└── test-phase3.sh                # Testy integracyjne
```

---

## Endpointy OIDC

### Discovery
```
GET /.well-known/openid-configuration
```

### JWKS
```
GET /jwks.json
GET /jwks.json?kid=<kid>    ← filtrowanie po kid
```

### Authorization flow

```
GET  /authorize              → serwuje signin.html (waliduje parametry OIDC)

POST /authorize/login
     Body: { sub, client_id, redirect_uri, scope, state, nonce,
             code_challenge, code_challenge_method, response_type }
     Response: { session_id, signing_input, user_name, user_username }

POST /authorize/confirm
     Body: { session_id, signature }   ← signature = base64url Ed25519
     Response: { redirect_url }        ← redirect_uri?code=...&state=...

POST /token
     Body: { grant_type, code, redirect_uri, client_id,
             code_verifier | client_secret }
     Response: { access_token, id_token, token_type, expires_in, scope }

GET  /userinfo
     Authorization: Bearer <access_token>
     Response: { sub, name, email, preferred_username }
```

---

## Admin API

Wszystkie endpointy `/admin/*` wymagają:
```
Authorization: Bearer <ADMIN_SECRET>
```

### Users — `/admin/users`

| Method | Path | Body / Params |
|--------|------|---------------|
| GET    | `/admin/users` | — |
| GET    | `/admin/users/:sub` | — |
| POST   | `/admin/users` | `{ username, name, email, hsm_url, kid, pubkey, clients[] }` |
| PATCH  | `/admin/users/:sub` | `{ name?, email?, hsm_url?, kid?, pubkey?, clients? }` |
| DELETE | `/admin/users/:sub` | — |

### Clients — `/admin/clients`

| Method | Path | Body |
|--------|------|------|
| GET    | `/admin/clients` | — |
| GET    | `/admin/clients/:id` | — |
| POST   | `/admin/clients` | `{ client_id, client_secret, name, redirect_uris[], scopes[], pkce, id_token_ttl, access_token_ttl }` |
| PATCH  | `/admin/clients/:id` | pola do aktualizacji |
| DELETE | `/admin/clients/:id` | — |

---

## Enrollment API — `/enrollment`

Rejestracja klucza HSM dla użytkownika. Używane przez `enrollment.html`.

```
POST /enrollment/validate
     Body: { enrollment_token }
     Response: { sub, username, hsm_url }

POST /enrollment/complete
     Body: { enrollment_token, kid, pubkey }   ← pubkey = hex 32-byte Ed25519
     Response: { ok: true }
```

`pubkey` musi być w formacie **hex** (32 bajty raw Ed25519 public key).
HSM zwraca pubkey jako base64 → konwersja przed wysłaniem:
```js
const pubkeyBytes = Uint8Array.from(atob(keyInfo.pubkey), c => c.charCodeAt(0));
const pubkey = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2,'0')).join('');
```

---

## Redis schema

```
user:{sub}        Hash {
  sub, username, name, email, hsm_url,
  kid,      ← ID klucza w HSM
  pubkey,   ← hex raw 32-byte Ed25519 public key
  clients,  ← JSON array client_ids
  created_at
}

client:{client_id}  Hash {
  client_id, client_secret, name,
  redirect_uris,  ← JSON array
  scopes,         ← JSON array
  pkce,           ← 'true'|'false'
  id_token_ttl, access_token_ttl, created_at
}

pending:{session_id}  JSON TTL 120s {
  sub, kid, client_id, scope, nonce,
  redirect_uri, code_challenge, signing_input, state
}

code:{code}       JSON TTL 60s {
  sub, client_id, scope, nonce,
  code_challenge, redirect_uri, id_token
}

access:{token}    JSON TTL 3600s {
  sub, client_id, scope
}
```

---

## Trusted App — flow

Przeglądarkowa SPA serwowana na `GET /authorize`.

```
s-login   → pole HSM URL (z cache localStorage)
              ↓ Continue
           Krok A: searchKeys(null, '^RVhUQUlE')
             sukces → openSearch=true, hasMobileApp=(keys>0)
             4xx   → openSearch=false → s-pin (fallback)

           Krok B: searchKeys(token?, '^ETSOIDC...')
             jeden klucz → auto-wybór
             wiele       → s-keys

s-keys    → lista kluczy, wybór

s-signing → "Waiting for approval…" (tryb mobilny)
              przycisk: "Use password instead" → s-pin
              po potwierdzeniu: POST /authorize/login → HSM sign → POST /authorize/confirm

s-pin     → pole hasła (fallback gdy brak mobilki lub anulowanie)
              po wpisaniu: autorizePassword → kontynuuj flow

s-error   → komunikat błędu
s-rejected → user anulował
```

### Opis kluczy HSM

- Klucze OIDC: `description = btoa('ETSOIDC' + sub)` — pattern wyszukiwania: `^` + btoa('ETSOIDC')
- Klucze mobilne: pattern `^RVhUQUlE` (base64 prefiksu EXTAID)

---

## HSM API (Encedo HEM)

Używane przez Trusted App i enrollment.html przez `hem-sdk.js`.

```
GET  {hsm_url}/api/keymgmt/search   ← searchKeys()
POST {hsm_url}/api/authorize-key-op ← authorizePassword() / authorizeRemote()
POST {hsm_url}/api/sign             ← exdsaSign()
POST {hsm_url}/api/checkin          ← hemCheckin()
```

### Podpisywanie EdDSA w hem-sdk.js

```js
// exdsaSign wysyła:
body.msg = toB64(strToBytes(signing_input))  // base64 of UTF-8 bytes
// zwraca: standard base64 signature → konwertuj do base64url dla JWT
```

---

## Ed25519 weryfikacja — backend

```js
// pubkey z Redis: hex raw 32-byte
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const pubkeyDer   = Buffer.concat([SPKI_PREFIX, Buffer.from(pubkeyHex, 'hex')]);
const publicKey   = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
verify(null, Buffer.from(signing_input), publicKey, Buffer.from(signature, 'base64url'));
```

---

## Testowanie

```bash
# Pełne testy integracyjne (faza 3)
bash test-phase3.sh

# Testowy Relying Party (port 9876)
node rp-server.mjs
# otwórz http://localhost:9876

# Health check
curl http://localhost:3000/health
```

### Nextcloud (user_oidc 8.6.1)

- Wymagane: `allow_local_remote_servers = true`, `allow_insecure_http = 1`
- `redirect_uri`: `http://localhost:8080/index.php/apps/user_oidc/code`
- JWKS cache nie uwzględnia `kid` — patch opisany w `nextcloud-jwks-kid-patch.md`

---

## Static pages

| URL | Plik |
|-----|------|
| `/authorize` | `signin.html` |
| `/enrollment` | `enrollment.html` |
| `/admin` | `admin-panel.html` |
| `/hem-sdk.js` | `hem-sdk.js` |
