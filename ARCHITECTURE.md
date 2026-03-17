# Encedo OIDC Provider — Dokumentacja Architektury

## Przegląd systemu

Encedo OIDC Provider to serwer tożsamości OpenID Connect, w którym każda operacja podpisywania JWT jest wykonywana **sprzętowo** — przez klucz prywatny zamknięty w urządzeniu HSM (Encedo HEM). Serwer nigdy nie posiada kluczy prywatnych użytkowników.

```
┌────────────────────────────────────────────────────────────────┐
│                        Encedo OIDC Provider                    │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  Admin Panel │  │  Trusted App │  │  Enrollment Page     │ │
│  │ (admin-panel │  │(trusted-app  │  │  (enrollment.html)   │ │
│  │   .html)     │  │  .html)      │  │                      │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘ │
│         │                 │                      │             │
│  ┌──────▼─────────────────▼──────────────────────▼───────────┐ │
│  │               Express.js API (src/)                       │ │
│  │  /admin/*   /authorize  /token  /userinfo  /enrollment    │ │
│  └──────────────────────────┬───────────────────────────────┘ │
│                             │                                  │
│                      ┌──────▼──────┐                          │
│                      │    Redis    │                          │
│                      │  (jedyna BD)│                          │
│                      └─────────────┘                          │
└────────────────────────────────────────────────────────────────┘
         │                    │
    ┌────▼────┐          ┌────▼────┐
    │ Encedo  │          │  RP     │
    │  HSM    │          │(np.     │
    │(per user│          │Next-    │
    │ device) │          │cloud)   │
    └─────────┘          └─────────┘
```

### Stack technologiczny

| Warstwa | Technologia |
|---------|-------------|
| Runtime | Node.js v22, ESM |
| Framework | Express 4 |
| Baza danych | Redis (node-redis v4) — jedyna baza |
| Kryptografia | Node.js `crypto` (built-in) — Ed25519 verify przez SPKI DER |
| HSM komunikacja | Encedo HEM SDK (`hem-sdk.js`) |
| Podpis JWT | Ed25519 (EdDSA) — klucz zawsze w HSM |

---

## Redis — schemat danych

```
user:{sub}          Hash    sub, username, name, email, hsm_url,
                            kid, pubkey (hex 32B), hw_attested,
                            clients (JSON array), enrolled_at, created_at

client:{client_id}  Hash    client_id, client_secret, name,
                            redirect_uris (JSON), scopes (JSON),
                            pkce ('true'/'false'), id_token_ttl,
                            access_token_ttl, created_at

pending:{session_id} JSON   TTL 120s — sesja podpisywania
                            { sub, kid, client_id, scope, nonce,
                              code_challenge, redirect_uri, state,
                              signing_input }

code:{code}         JSON    TTL 60s — jednorazowy auth code
                            { sub, client_id, scope, nonce,
                              code_challenge, redirect_uri, id_token }

access:{token}      JSON    TTL 3600s — access token
                            { sub, client_id, scope }

enrollment:{token}  JSON    TTL 24h → 30min po otwarciu
                            { sub, username, challenge }

security:log        ZSET    score=timestamp_ms, value=JSON event
security:events     Pub/Sub real-time stream security eventów

users               Set     wszystkie sub wartości
clients             Set     wszystkie client_id wartości
rl:{prefix}:{id}    String  TTL=window — licznik rate limit
```

---

## Flow 1: Dodanie użytkownika (Admin Panel)

```
Admin Panel                    Backend                        Redis
    │                              │                             │
    │  POST /admin/users           │                             │
    │  { username, email,          │                             │
    │    name, hsm_url }           │                             │
    │─────────────────────────────►│                             │
    │                              │ Validate: email, url,       │
    │                              │ username charset            │
    │                              │ Check username unique       │
    │                              │─────────────────────────────►
    │                              │ hSet user:{sub}             │
    │                              │ sAdd users                  │
    │                              │ set enrollment:{token} 24h  │
    │                              │◄────────────────────────────│
    │  201 { sub, enrollment_url } │                             │
    │◄─────────────────────────────│                             │
    │                              │                             │
```

`enrollment_url` ma postać: `https://oidc.example.com/enrollment#token=XXX`

Token jest w **URL fragment** (`#`) — nie trafia do access logów serwera ani nagłówka Referer.

Admin przekazuje link użytkownikowi kanałem out-of-band (email, komunikator).

---

## Flow 2: Dodanie klienta OIDC (Admin Panel)

```
Admin Panel                    Backend                        Redis
    │                              │                             │
    │  POST /admin/clients         │                             │
    │  { name, redirect_uris,      │                             │
    │    scopes, pkce:true,        │                             │
    │    id_token_ttl,             │                             │
    │    access_token_ttl }        │                             │
    │─────────────────────────────►│                             │
    │                              │ Validate: redirect_uris     │
    │                              │ (https lub localhost),      │
    │                              │ scopes allowlist,           │
    │                              │ TTL 60–86400s,              │
    │                              │ pkce=boolean                │
    │                              │ Generate client_id (UUID)   │
    │                              │ Generate client_secret      │
    │                              │─────────────────────────────►
    │                              │ hSet client:{client_id}     │
    │                              │ sAdd clients                │
    │                              │◄────────────────────────────│
    │  201 { client_id,            │                             │
    │        client_secret }       │                             │
    │◄─────────────────────────────│                             │
```

`client_secret` pojawia się **tylko raz** w odpowiedzi na tworzenie. Możliwa rotacja przez `POST /admin/clients/:id/rotate-secret`.

Walidacja `redirect_uris`: tylko HTTPS (http dozwolone wyłącznie dla localhost).

---

## Flow 3: Enrollment — rejestracja klucza HSM

Enrollment to jednorazowe powiązanie konta użytkownika z kluczem Ed25519 w konkretnym urządzeniu HSM.

```
enrollment.html                  HSM (my.ence.do)               Backend
    │                                │                              │
    │  [User otwiera enrollment URL] │                              │
    │  GET /enrollment/validate      │                              │
    │─────────────────────────────────────────────────────────────►│
    │                                │              Read enrollment │
    │                                │              session z Redis │
    │                                │              Generuj 32-byte │
    │                                │              challenge       │
    │                                │              Skróć TTL→30min │
    │  { sub, username, hsm_url,     │                              │
    │    challenge }                 │                              │
    │◄────────────────────────────────────────────────────────────-│
    │                                │                              │
    │  [User wpisuje hasło HSM]      │                              │
    │                                │                              │
    │  authorizePassword(            │                              │
    │    keymgmt:gen)                │                              │
    │───────────────────────────────►│                              │
    │  genToken                      │                              │
    │◄───────────────────────────────│                              │
    │                                │                              │
    │  createKeyPair(genToken,       │                              │
    │    label, 'ED25519', descrB64) │                              │
    │  descrB64 = btoa('ETSOIDC'+sub)│                              │
    │───────────────────────────────►│                              │
    │  { kid }   ← SHA1[:16](pubkey) │                              │
    │◄───────────────────────────────│                              │
    │                                │                              │
    │  authorizePassword(            │                              │
    │    keymgmt:use:{kid})          │                              │
    │───────────────────────────────►│                              │
    │  useToken                      │                              │
    │◄───────────────────────────────│                              │
    │                                │                              │
    │  getPubKey(useToken, kid)      │                              │
    │───────────────────────────────►│                              │
    │  { pubkey: base64 }            │                              │
    │◄───────────────────────────────│                              │
    │  pubkeyHex = atob(pubkey)→hex  │                              │
    │                                │                              │
    │  [KEY POSSESSION PROOF]        │                              │
    │  exdsaSign(useToken, kid,      │                              │
    │    challenge)                  │                              │
    │───────────────────────────────►│                              │
    │  signature (Uint8Array→b64url) │                              │
    │◄───────────────────────────────│                              │
    │                                │                              │
    │  [HSM ATTESTATION]             │                              │
    │  GET /api/system/config/       │                              │
    │    attestation (useToken)      │                              │
    │───────────────────────────────►│                              │
    │  { genuine }                   │                              │
    │◄───────────────────────────────│                              │
    │                                │                              │
    │  POST /enrollment/submit       │                              │
    │  { token, hsm_url, kid,        │                              │
    │    pubkey, signature, genuine }│                              │
    │─────────────────────────────────────────────────────────────►│
    │                                │  1. Validate pubkey (64 hex)│
    │                                │  2. Validate kid =          │
    │                                │     SHA1[:16](pubkey)       │
    │                                │  3. getDel enrollment token │
    │                                │     → pobierz challenge     │
    │                                │  4. Verify Ed25519:         │
    │                                │     sign(challenge)==pubkey │
    │                                │  5. Check duplicate pubkey  │
    │                                │  6. hw_attested=genuine?    │
    │                                │     (TODO: api.encedo.com)  │
    │                                │  7. hSet user: kid, pubkey, │
    │                                │     hw_attested             │
    │  { ok, kid, hw_attested }      │                              │
    │◄────────────────────────────────────────────────────────────-│
```

### Właściwości bezpieczeństwa enrollment

| Właściwość | Mechanizm |
|------------|-----------|
| Jednorazowy token | `getDel` — token znika po pierwszym użyciu |
| Krótkie okno czasowe | TTL 24h → 30min po otwarciu strony |
| Token niewidoczny w logach | URL fragment `#token=` |
| Proof-of-possession | Backend weryfikuje Ed25519(challenge, pubkey) |
| kid weryfikowalny | `kid = SHA1[:16](pubkey)` — deterministyczny |
| Unikalność klucza | Blokada duplikatów pubkey między userami |
| Sprzętowa atestacja | `genuine` z HSM → `hw_attested` (TODO: walidacja) |

**Czego enrollment NIE gwarantuje (jeszcze):**
- Dowodu, że klucz jest w hardware — to zadanie atestacji przez `api.encedo.com`

---

## Flow 4: Autoryzacja OIDC (Trusted App)

Standard OpenID Connect Authorization Code Flow z PKCE. Podpisywanie JWT wykonuje HSM użytkownika, nie serwer.

### 4a. Inicjacja przez RP

```
Relying Party (np. Nextcloud)          Backend
    │                                      │
    │  GET /authorize                      │
    │  ?client_id=&redirect_uri=           │
    │  &response_type=code                 │
    │  &scope=openid profile email         │
    │  &code_challenge=<SHA256(verifier)>  │
    │  &code_challenge_method=S256         │
    │  &state=&nonce=                      │
    │─────────────────────────────────────►│
    │                                      │ Validate: client exists,
    │                                      │ redirect_uri w allowlist,
    │                                      │ scope dozwolony,
    │                                      │ PKCE wymagane?,
    │                                      │ nonce≤256, state≤512,
    │                                      │ code_challenge=43 b64url
    │  200 signin.html                │
    │◄─────────────────────────────────────│
```

### 4b. Trusted App — wykrywanie klucza

```
Trusted App (przeglądarka)             HSM (my.ence.do)
    │                                      │
    │  hemCheckin()                        │
    │  [3-way handshake przez broker]      │
    │─────────────────────────────────────►│
    │                                      │
    │  searchKeys(null, '^RVhUQUlE')       │  Krok A: czy jest mobile app?
    │─────────────────────────────────────►│
    │  keys (0 = brak, >0 = jest)          │
    │◄─────────────────────────────────────│
    │                                      │
    │  searchKeys(null, '^ETSOIDC...')     │  Krok B: szukaj kluczy OIDC
    │─────────────────────────────────────►│  (opis = btoa('ETSOIDC'+sub))
    │  [{kid, label, description}...]      │
    │◄─────────────────────────────────────│
    │                                      │
    │  [1 klucz → auto-wybór]              │
    │  [>1 kluczy → ekran wyboru]          │
    │  [4xx → ekran hasła]                 │
```

### 4c. Autoryzacja klucza i podpisanie JWT

```
Trusted App                HSM                    Backend (OIDC Server)
    │                        │                           │
    │  [Ścieżka A: mobilna]  │                           │
    │  authorizeRemote(scope)│                           │
    │───────────────────────►│ (push notification        │
    │  polling...            │  do mobile app)           │
    │                        │                           │
    │  [Ścieżka B: hasło]    │                           │
    │  authorizePassword(pwd,│                           │
    │    keymgmt:use:{kid})  │                           │
    │───────────────────────►│                           │
    │  useToken              │                           │
    │◄───────────────────────│                           │
    │                        │                           │
    │  POST /authorize/login │                           │
    │  { sub, client_id,     │                           │
    │    redirect_uri, scope,│                           │
    │    nonce, code_challenge, ... }                    │
    │──────────────────────────────────────────────────►│
    │                        │   Lookup user (sub/name)  │
    │                        │   Sprawdź: user∈client    │
    │                        │   Sprawdź: enrolled       │
    │                        │   Buduj JWT header+payload│
    │                        │   signing_input =         │
    │                        │   b64url(hdr).b64url(pay) │
    │                        │   Zapisz pending:{session}│
    │  { session_id,         │                           │
    │    signing_input }     │                           │
    │◄──────────────────────────────────────────────────│
    │                        │                           │
    │  exdsaSign(useToken,   │                           │
    │    kid, signing_input) │                           │
    │───────────────────────►│ Klucz prywatny nigdy      │
    │  signature (bytes)     │ nie opuszcza HSM          │
    │◄───────────────────────│                           │
    │                        │                           │
    │  POST /authorize/confirm                           │
    │  { session_id, signature, kid }                    │
    │──────────────────────────────────────────────────►│
    │                        │   getDel pending session  │
    │                        │   Sprawdź kid=pending.kid │
    │                        │   Verify Ed25519:         │
    │                        │   pubkey z Redis (nie     │
    │                        │   od frontendu!)          │
    │                        │   id_token = signing_input│
    │                        │     + "." + signature     │
    │                        │   Zapisz code:{code}      │
    │  { redirect_url }      │                           │
    │◄──────────────────────────────────────────────────│
    │                        │                           │
    │  [odliczanie 5s]       │                           │
    │  window.location = redirect_url?code=&state=       │
```

### 4d. Wymiana kodu na tokeny

```
Relying Party                          Backend
    │                                      │
    │  POST /token                         │
    │  { grant_type=authorization_code,    │
    │    code, redirect_uri,               │
    │    client_id, code_verifier }        │
    │─────────────────────────────────────►│
    │                                      │ getDel code:{code}
    │                                      │ Sprawdź: client_id match
    │                                      │ Sprawdź: redirect_uri match
    │                                      │ PKCE: SHA256(verifier)==challenge
    │                                      │   (timing-safe compare)
    │                                      │ lub client_secret compare
    │                                      │   (timing-safe)
    │                                      │ Odczytaj id_token (pre-signed)
    │                                      │ Generuj access_token (random)
    │                                      │ Zapisz access:{token}
    │  { access_token, id_token,           │
    │    token_type, expires_in, scope }   │
    │◄─────────────────────────────────────│
```

### 4e. Weryfikacja JWT przez RP

```
Relying Party                          Backend (JWKS)
    │                                      │
    │  GET /jwks.json[?kid=]               │
    │─────────────────────────────────────►│
    │                                      │ Odczytaj wszystkich userów
    │                                      │ Zbuduj JWK dla każdego
    │                                      │ (kty=OKP, crv=Ed25519)
    │                                      │ Cache-Control: max-age=3600
    │  { keys: [{kty,crv,x,kid,alg,use}] } │
    │◄─────────────────────────────────────│
    │                                      │
    │  [RP weryfikuje JWT lokalnie:]       │
    │  Znajdź klucz po kid z JWT header   │
    │  Verify Ed25519(header.payload,      │
    │    signature, publicKey)             │
    │  Sprawdź: iss, aud, exp, nonce       │
```

---

## Architektura bezpieczeństwa JWT

```
Backend buduje signing_input:
  header  = { alg: "EdDSA", kid: "3ce207..." }
  payload = { iss, sub, aud, iat, exp, nonce, email, name, ... }
  signing_input = base64url(header) + "." + base64url(payload)
                                          ▲
                                          │ backend, nie frontend
                                          │ kid pochodzi z Redis

HSM podpisuje signing_input → signature (64 bajty, Ed25519)

JWT = signing_input + "." + base64url(signature)
       └─ zbudowany przez backend ─┘   └── HSM ──┘
```

**Dlaczego to bezpieczne:**
- `signing_input` buduje backend — frontend nie może podmienić `kid`, `sub`, `aud`, `exp`
- `pubkey` do weryfikacji pochodzi z Redis — frontend nie może go podmienić
- `kid` zakotwiczony w `pending` session przy loginie — niemożliwa podmiana mid-flow
- Klucz prywatny nigdy nie opuszcza HSM

---

## Middleware i zabezpieczenia serwera

### Security headers (wszystkie odpowiedzi)
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=63072000 (tylko prod)
```

### CORS
- Publiczne endpointy OIDC: `Access-Control-Allow-Origin: *`
- `/admin/*`: brak CORS (same-origin only)

### Rate limiting (Redis-based, multi-instance)
| Endpoint | Limit |
|----------|-------|
| `POST /authorize/login` | 20 req/min per `client_id` |
| `POST /authorize/confirm` | 10 req/min per IP |
| `POST /token` | 20 req/min per IP |
| `POST /admin/*` | 60 req/min per IP |

### Admin API
- `ADMIN_ALLOWED_IPS`: CIDR allowlist (opcjonalny, uzupełnia VPN)
- `timingSafeEqual` dla porównania tokena
- Brak `ADMIN_SECRET` → 500 (fail-safe)

### Walidacja inputu
Wszystkie endpointy mają walidację przez `src/middleware/validate.js`:
- Email: format RFC 5322
- URL: protokół, brak credentiali, https-only (opcjonalnie)
- Username: `[a-zA-Z0-9._@-]`, 2–64 znaki
- `code_challenge`: dokładnie 43 base64url (RFC 7636)
- `code_verifier`: 43–128 unreserved chars (RFC 7636)
- Signature Ed25519: ~86 base64url chars
- TTL: 60–86400 sekund
- Body: limit 32 KB

---

## Audit log

Każde zdarzenie bezpieczeństwa trafia do:
1. **Redis Pub/Sub** `security:events` — real-time stream dla konsumentów (SIEM, monitoring)
2. **Redis ZSET** `security:log` — persystentny log, score=timestamp_ms, max 20 000 wpisów

### Typy zdarzeń
| Typ | Zdarzenie |
|-----|-----------|
| `auth.login.ok/fail` | Próba logowania OIDC |
| `auth.signature.ok/fail` | Weryfikacja podpisu JWT |
| `auth.token.issued` | Wydanie access+id token |
| `admin.auth.fail` | Nieudana autoryzacja Admin API |
| `admin.user.create/delete/patch` | Operacje CRUD na userach |
| `admin.client.create/delete/rotate_secret` | Operacje na klientach |
| `enrollment.ok/fail` | Rejestracja klucza HSM |
| `ratelimit.hit` | Przekroczenie rate limit |

### Przykład konsumenta

```javascript
const sub = redisClient.duplicate();
await sub.connect();
await sub.subscribe('security:events', (msg) => {
  const ev = JSON.parse(msg);
  // { ts, type, sub?, ip?, client_id?, reason?, hw_attested? }
});

// Zapytanie historyczne (ostatnia godzina):
const from = Date.now() - 3_600_000;
const events = await redis.zRangeByScore('security:log', from, '+inf');
```

---

## Konfiguracja środowiska

```env
PORT=3000
NODE_ENV=production
ISSUER=https://oidc.example.com
REDIS_URL=redis://127.0.0.1:6379
ADMIN_SECRET=<losowy, min. 32 znaki>
ADMIN_ALLOWED_IPS=10.8.0.0/24,127.0.0.1    # opcjonalne, sieć VPN
TRUST_PROXY=1                                # jeśli za nginx/caddy
SECURITY_LOG_MAX=20000                       # max wpisów w ZSET
```

---

## Znane ograniczenia i TODO

| # | Opis | Priorytet |
|---|------|-----------|
| **T1** | Atestacja HSM: walidacja `genuine` przez `api.encedo.com` + sprawdzenie timestamp ±60s | Wysoki |
| **T2** | Re-enrollment nie unieważnia aktywnych `access:*` tokenów (TTL do 1h) | Średni |
| **T3** | `security:log` w tym samym Redis co dane — attacker z dostępem do Redis może czyścić logi | Średni |
| **T4** | Brak RBAC w Admin API (jeden poziom uprawnień) | Niski |
| **T5** | `hsm_url` użytkownika nie jest weryfikowany pod kątem osiągalności przy enrollment | Niski |
