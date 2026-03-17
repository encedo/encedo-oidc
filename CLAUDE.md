# Encedo OIDC Provider — instrukcje dla Claude Code

## Referencja SDK
Dokumentacja HEM SDK: `~/develop/sdk-php/HEM.php`
Czytaj tylko gdy potrzebujesz znać API HSM.

---

## Status projektu — Faza 4 GOTOWA

### Backend (`src/`) — 100%
- ✅ `GET /authorize` — walidacja OIDC params, serwuje `signin.html`
- ✅ `POST /authorize/login` — lookup usera (po `sub` lub `username`), buduje `signing_input`, sesja Redis TTL 120s
- ✅ `POST /authorize/confirm` — weryfikacja Ed25519, składa JWT, emituje code
- ✅ `POST /token` — PKCE S256, zwraca pre-signed `id_token` + `access_token`
- ✅ `GET /userinfo` — Bearer token
- ✅ `GET /jwks.json` + `?kid=` filtr
- ✅ `GET /.well-known/openid-configuration`
- ✅ Admin API: CRUD users + clients
- ✅ `privkey` usunięty z Redis schema i z odpowiedzi `/authorize/login`

### Trusted App (`signin.html`) — 100%
- ✅ Ekran Login — tylko HSM URL (bez pola username, bez pola hasła)
- ✅ Krok A: `searchKeys(null, '^RVhUQUlE')` — wykrycie trybu mobilnego
- ✅ Krok B: `searchKeys(token?, '^ETSOIDC...')` — wyszukanie kluczy OIDC
- ✅ Auto-wybór przy jednym kluczu (skip s-keys)
- ✅ Ekran s-keys — lista kluczy, wybór
- ✅ Ekran s-signing — spinner, "Waiting for approval…" + przycisk "Use password instead"
- ✅ Ekran s-pin — fallback z hasłem (4xx z HSM lub anulowanie mobilnego)
- ✅ `doCancelMobile()` — anuluje mobilny polling (`currentOpId = null`), przechodzi do hasła
- ✅ `finalizeSign()` — wspólna logika: `/authorize/login` → HSM sign → `/authorize/confirm` → countdown 5s → redirect
- ✅ Countdown 5→1 przed przekierowaniem do RP

### enrollment.html — 100%
- ✅ pubkey konwertowany base64 → hex przed wysłaniem do backendu
- ✅ description: `btoa('ETSOIDC' + sub)` (bez client_id)

---

## Stack

```
Node.js v22 ESM
Express 4
Redis (node-redis v4) — jedyna baza
crypto (built-in) — Ed25519 verify przez SPKI DER reconstruction
zero zewnętrznych deps krypto
```

## Struktura projektu

```
encedo-oidc/
├── src/
│   ├── app.js
│   ├── routes/oidc.js          ← wszystkie endpointy OIDC
│   ├── routes/enrollment.js
│   ├── routes/adminUsers.js
│   ├── routes/adminClients.js
│   ├── middleware/auth.js
│   ├── middleware/errorHandler.js
│   └── services/redis.js
├── signin.html            ← Trusted App SPA (produkcja)
├── enrollment.html             ← rejestracja kluczy HSM
├── admin-panel.html
├── hem-sdk.js                  ← Encedo HEM JavaScript SDK
├── rp-server.mjs               ← test RP (port 9876)
└── test-phase3.sh
```

---

## Kluczowe decyzje architektoniczne

### signing_input
Backend buduje pełny `signing_input = base64url(header).base64url(payload)`.
Frontend tylko podpisuje — nie buduje JWT.

### Weryfikacja Ed25519 w backendzie
```javascript
// pubkey z Redis: hex-encoded raw 32-byte public key
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const pubkeyDer   = Buffer.concat([SPKI_PREFIX, Buffer.from(pubkeyHex, 'hex')]);
const publicKey   = createPublicKey({ key: pubkeyDer, format: 'der', type: 'spki' });
verify(null, Buffer.from(signing_input), publicKey, Buffer.from(signature, 'base64url'));
```

### exdsaSign w hem-sdk.js
```javascript
// msg = base64 of UTF-8 bytes of signing_input — musi być tak, nie zmieniać
body.msg = toB64(strToBytes(msg));
// HSM zwraca standard base64 → konwertuj do base64url dla JWT
```

### pubkey encoding
- HSM zwraca pubkey jako **standard base64**
- Backend przechowuje jako **hex** (32 bajty raw)
- Enrollment.html konwertuje: `atob(keyInfo.pubkey)` → bytes → hex

### Key description format
```javascript
// Przy enrollmencie:
description = btoa('ETSOIDC' + sub)
// Przy wyszukiwaniu OIDC kluczy:
searchKeys(token, '^' + btoa('ETSOIDC'))
// Przy wykrywaniu mobilki:
searchKeys(null, '^RVhUQUlE')
```

### Sub-based user lookup
Backend `/authorize/login` akceptuje `sub` (direct Redis lookup) lub `username` (scan):
```javascript
if (subParam?.trim()) {
  const raw = await redis.hGetAll(`user:${subParam.trim()}`);
  user = raw?.sub ? raw : null;
} else {
  user = await findUserByUsername(username.trim());
}
```

### hem-sdk.js — obsługa błędów HTTP
`#req` łapie JSON.parse errors (pusta odpowiedź 401):
```javascript
try { data = await res.json(); } catch { data = null; }
// potem normalnie: if (!res.ok) throw new HemError(...)
```
Bez tego 401 z pustym body rzuca SyntaxError zamiast HemError — trusted-app nie rozpoznaje go jako 4xx.

### Mobile cancel — currentOpId
```javascript
let currentOpId = null;
// przed authorizeRemote:
const opId = Symbol();
currentOpId = opId;
// po powrocie:
if (currentOpId !== opId) return; // anulowane
// doCancelMobile():
currentOpId = null;  // polling działa dalej w tle, ale wynik ignorowany
```

---

## Redis schema

```
user:{sub} → Hash {
  sub, username, name, email, hsm_url,
  kid,     ← ID klucza w HSM
  pubkey,  ← hex raw 32-byte Ed25519 public key
  clients, ← JSON array client_ids
  created_at
}
// UWAGA: privkey USUNIĘTY (był tylko w Fazie 3 SIM)

client:{client_id} → Hash { ... }
pending:{session_id} → JSON TTL 120s { ... }
code:{code} → JSON TTL 60s { ... }
access:{token} → JSON TTL 3600s { ... }
```

---

## Trusted App — flow szczegółowy

```
doLogin()
  → hemCheckin()
  → Krok A: searchKeys(null, '^RVhUQUlE')
      sukces → session.openSearch=true, session.hasMobileApp=(keys.length>0)
      4xx    → session.openSearch=false → showPinScreen() [pendingAfterPin='search']
  → Krok B (tylko gdy openSearch):
      searchKeys(null, '^ETSOIDC...')
      zero kluczy → błąd
      jeden klucz → doSelectKey()
      wiele kluczy → showScreen('s-keys')

doSubmitPin()             ← user podał hasło
  pendingAfterPin='search':
    authorizePassword → searchKeys → renderKeyList → doSelectKey()
  pendingAfterPin='use':
    session.password=pin → doSelectKey()

doSelectKey()
  session.password → authorizePassword(scope) → finalizeSign()
  session.hasMobileApp → showScreen('s-signing') z cancel btn
                       → authorizeRemote(scope) → if cancelled → ignoruj
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
POST {hsm_url}/api/checkin             ← hemCheckin()
POST {hsm_url}/api/keymgmt/search      ← searchKeys(token, pattern)
POST {hsm_url}/api/authorize-key-op    ← authorizePassword(pwd, scope) / authorizeRemote(scope)
POST {hsm_url}/api/sign                ← exdsaSign(token, kid, msg)
```

---

## Znane kwestie

1. Nextcloud wymaga `allow_local_remote_servers = true` i `allow_insecure_http = 1` dla dev
2. Nextcloud `redirect_uri`: `http://localhost:8080/index.php/apps/user_oidc/code`
3. JWKS cache w Nextcloud nie uwzględnia `kid` — patch opisany w `nextcloud-jwks-kid-patch.md`
4. Ed25519 Web Crypto: Chrome 105+ / Firefox 113+ wymagane (enrollment.html używa Web Crypto)
5. HEM SDK `searchKeys` bez tokena — domyślna konfiguracja HSM pozwala na otwarty search; 4xx = wymaga auth
