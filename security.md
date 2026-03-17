# Analiza ryzyka bezpieczeństwa — Encedo OIDC Provider

> Perspektywa hakera. Stan kodu: 2026-03-17 (po poprawkach Fazy 4).
> Severity: CRITICAL / HIGH / MEDIUM / LOW

---

## Tabela ryzyk — stan aktualny

| ID  | Severity | Opis                                                  | Status              |
|-----|----------|-------------------------------------------------------|---------------------|
| C1  | CRITICAL | Atestacja HSM niefunkcjonalna — `hw_attested` zawsze true | TODO              |
| H1  | HIGH     | Admin bez restrykcji sieciowych domyślnie             | Env var (doc)       |
| H2  | HIGH     | Rate limit fail-open przy awarii Redis                | Otwarte             |
| H3  | HIGH     | findUserByUsername O(n) scan — DoS                    | Otwarte             |
| H4  | HIGH     | ID tokeny nieodwołalne — brak jti revocation list     | Otwarte             |
| M1  | MEDIUM   | `user_tokens:{sub}` TTL — rewokacja zawodna           | Otwarte             |
| M2  | MEDIUM   | JWT payload z PII w logach produkcyjnych              | Otwarte             |
| M3  | MEDIUM   | Brak OIDC logout endpoint                             | Otwarte             |
| M4  | MEDIUM   | `enrollment_token` w GET /admin/users/:sub            | Otwarte             |
| M5  | MEDIUM   | Security log tylko w Redis — podatny na utratę        | Otwarte             |
| M6  | MEDIUM   | `client_secret` w POST body                          | Otwarte             |
| M7  | MEDIUM   | CSP: `script-src 'unsafe-inline'` — XSS nadal groźny  | Częściowo           |
| L1  | LOW      | CORS `*` na `/token` + brak PKCE = code theft risk    | Otwarte             |
| L2  | LOW      | Admin rate limit per-IP bez network isolation         | Otwarte             |
| L3  | LOW      | PKCE opcjonalne per klient                            | Otwarte             |
| L4  | LOW      | JWKS — brak server-side cache, Redis hit per request  | Otwarte             |
| L5  | LOW      | Brak `/token/revoke` (RFC 7009)                      | Otwarte             |

### Naprawione od poprzedniej analizy
| ID  | Opis                                           |
|-----|------------------------------------------------|
| ~~C2~~ | CSP dodane (connect-src, frame-ancestors, base-uri) |
| ~~H5~~ | Enrollment: TTL reset bug, rate limit 10/5 per min |
| ~~H6~~ | CORS zawężone do OIDC protocol endpoints       |
| ~~H7~~ | Access tokeny rewokowane przy DELETE usera     |
| ~~M8~~ | `/authorize-test` usunięty                    |
| ~~L1~~ | `jti` dodane do ID tokenów                    |
| ~~H3~~ | SSRF: HTTPS wymuszony na hsm_url, RFC1918 dozwolone (PPA) |

---

## CRITICAL

### C1 — Atestacja HSM niefunkcjonalna
**Plik:** `src/services/attestation.js`

`validateAttestation()` zwraca `hw_attested: 'true'` dla każdego niepustego stringa.
Attakujący podaje `genuine: "x"` i uzyskuje `hw_attested=true` w profilu.

**Atak:**
1. Hacker posiada token enrollmentu (np. przechwycony email)
2. Generuje lokalnie parę kluczy Ed25519
3. Wywołuje `/enrollment/validate` — dostaje challenge
4. Podpisuje challenge swoim kluczem
5. Wysyła `genuine: "fake"` — system akceptuje jako hw_attested=true
6. Klucz hacker's key zarejestrowany jako "hardware-backed" — może logować się jako ten użytkownik

**Skutek:** `hw_attested` jest bezużytecznym polem dopóki walidacja nie jest zaimplementowana.
Każda logika biznesowa opierająca się na `hw_attested=true` jest fałszywa.

**Fix:** Zaimplementować POST do brokera api.encedo.com. Rozważyć odrzucanie enrollmentu
gdy `hw_attested=false` lub co najmniej traktować go jako niższy poziom zaufania.

---

## HIGH

### H1 — Admin bez restrykcji sieciowych domyślnie
**Plik:** `src/middleware/auth.js:52`

```javascript
if (!allowedEnv) return next(); // Not configured — trust network layer
```

Bez `ADMIN_ALLOWED_IPS` admin API dostępne z całego internetu. Jedyna linia obrony:
`ADMIN_SECRET`. Rate limit admina: 60 req/min, ale **per IP** — rozproszony atak
z wielu IP = brak efektywnego limitu.

**Atak:** Distributed brute-force ADMIN_SECRET z 100 IP = 6000 prób/min.
Przy 8-znakowym ASCII sekrecie (94^8 ≈ 6×10^15) — długo, ale przy słabym sekrecie realne.

**Uwaga architektoniczna:** Admin panel będzie za proxy z filtracją. Dopóki proxy nie jest
wdrożone, `ADMIN_ALLOWED_IPS` MUSI być ustawione.

**Fix operacyjny:** Zawsze ustawiać `ADMIN_ALLOWED_IPS` w produkcji.
Dodać dedykowany niższy rate limit na nieudane próby auth admina (5 fail/min → blokada IP).

---

### H2 — Rate limit fail-open przy awarii Redis
**Plik:** `src/middleware/rateLimit.js:37`

```javascript
} catch {
  // Fail open — Redis outage must not block authentication
}
```

Celowy restart lub OOM Redis wyłącza wszystkie rate limity jednocześnie.
Atakujący może spowodować Redis failure (np. przez wysyłanie ogromnych payloadów
powodujących memory pressure) a następnie przeprowadzić nieograniczony atak.

**Atak:**
1. Zalej Redis dużymi wartościami przez `/authorize/login` (body limit 32kb → wolno)
2. Gdy Redis pod presją → rate limit wyłączony
3. Brute-force loginów lub enumerate subów bez blokady

**Fix:** In-memory LRU counter jako fallback (per-process, nie multi-instance).
Przynajmniej zabezpiecza przed prostym Redis-OOM atakiem.

---

### H3 — findUserByUsername: O(n) sequential scan
**Plik:** `src/routes/oidc.js:43`

```javascript
for (const sub of subs) {
  const u = await redis.hGetAll(`user:${sub}`); // sequential, jeden request na raz
  if (u?.username === username) return u;
}
```

Przy N użytkownikach = N sequential Redis roundtrips. Bez indexu username→sub.

**Atak:** Distributed DoS — wiele IP, każdy uderza w `/authorize/login` z `username` (nie `sub`).
Rate limit 20/min per `client_id`, ale wiele clientów × wiele IP = znaczne obciążenie Redis.
Przy 10 000 userów × 1 request = 10 000 Redis calls per login attempt.

**Fix:** `redis.hSet('username_index', username, sub)` przy CREATE/PATCH/DELETE.
Lookup w O(1): `const sub = await redis.hGet('username_index', username)`.

---

### H4 — ID tokeny nieodwołalne
**Plik:** `src/routes/oidc.js`

Access tokeny są odwoływalne (Redis, `user_tokens:{sub}`). ID tokeny (JWT) — nie.
JWT jest podpisany przez HSM. Podpis jest ważny przez cały czas `exp`, niezależnie od
statusu użytkownika w systemie.

**Scenariusz:**
1. Admin usuwa użytkownika — access tokeny kasowane natychmiast
2. RP trzyma `id_token` przez godzinę (typowe dla SSO sessions)
3. RP nie weryfikuje `id_token` przez introspection, tylko przez JWKS + podpis
4. Klucz publiczny usera jest usunięty z Redis → JWKS go nie zawiera
5. Ale RP może mieć JWKS w cache przez `max-age=3600` — stary klucz nadal znany
6. Przez do godziny RP akceptuje ID token usuniętego użytkownika

**Skutek:** Okno 0–3600s w którym ID token jest ważny mimo usunięcia użytkownika.

**Fix:** Dodać `jti` revocation ZSET w Redis. Przy DELETE: dodać `jti` wszystkich
znanych tokenów do `revoked_jti` SET. Wymaga jednak aby RP weryfikował przez
introspection endpoint (`/token/introspect` — brak) lub krótszego TTL.
Pragmatyczne rozwiązanie: skrócić `id_token_ttl` do 5 minut, wymusić refresh.

---

## MEDIUM

### M1 — `user_tokens:{sub}` TTL — rewokacja zawodna
**Plik:** `src/routes/oidc.js:424`

```javascript
await redis.sAdd(`user_tokens:${codeData.sub}`, accessKey);
await redis.expire(`user_tokens:${codeData.sub}`, accessTokenTtl + 60);
```

Przy każdym nowym logowaniu `expire` jest resetowany. Problem: jeśli użytkownik
ma 5 tokenów z różnymi TTL i wyloguje się na chwilę, a potem zaloguje ponownie —
`user_tokens` SET może wygasnąć zanim któryś ze starszych tokenów. Nowe tokeny
dodane po wygaśnięciu SETu nie dziedziczą starych wpisów.

**Skutek:** Po wygaśnięciu `user_tokens:{sub}` (co może nastąpić przed wygaśnięciem
starszego tokenu), `DELETE user` nie usunie wszystkich tokenów. Stary access token
może przeżyć deletion.

**Fix:** Używać `redis.expireAt` z maksymalnym `exp` spośród wszystkich tokenów,
lub nie ustawiać TTL na SETcie i czyścić go zawsze razem z userem.

---

### M2 — JWT payload z PII w logach produkcyjnych
**Plik:** `src/routes/oidc.js:339-341`

```javascript
console.log('  JWT payload :', JSON.stringify(decodedPayload, null, 2)...);
console.log('  id_token :', id_token.slice(0, 60) + '…');
```

Każdy udany login loguje pełny JWT payload: `email`, `name`, `preferred_username`, `sub`.
W aggregatorach logów (ELK, Loki, CloudWatch) = PII w logach = problem RODO.

**Fix:** Usunąć lub ograniczyć do `NODE_ENV !== 'production'`. Logować tylko `sub`, `client_id`, `jti`.

---

### M3 — Brak OIDC logout endpoint
**Plik:** brak

Nie istnieje `end_session_endpoint` w discovery. RP nie może poinformować IdP
o wylogowaniu użytkownika. Sesja HSM (tokeny w przeglądarce) pozostaje aktywna.

**Scenariusz ataku:**
1. Użytkownik loguje się z publicznego komputera
2. Wylogowuje się z RP (RP kasuje swoje ciasteczka)
3. Atakujący otwiera przeglądarkę — w `signin.html` mogą pozostawać dane sesyjne
   (jeśli SPA nie czyści stanu przy wylogowaniu)
4. RP nie może wymusić logout na poziomie IdP

**Fix:** Zaimplementować `GET /logout?id_token_hint=...&post_logout_redirect_uri=...`
(per OpenID Connect RP-Initiated Logout 1.0). Endpoint powinien: skasować pending sessions,
opcjonalnie cofnąć access token, przekierować do RP.

---

### M4 — `enrollment_token` w GET /admin/users/:sub
**Plik:** `src/routes/adminUsers.js:32`

`deserialize()` zwraca ALL pola hash Redis — włącznie z `enrollment_token` jeśli
użytkownik jeszcze się nie zarejestrował. Token jest ważny przez 24h od stworzenia konta.

**Atak:** Admin z dostępem odczytu API (np. helpdesk operator) może pobrać token
enrollmentu i zarejestrować własny klucz zamiast klucza użytkownika.
Prowadzi do przejęcia konta.

**Fix:** Wyłączyć `enrollment_token` z odpowiedzi GET. Token zwracać tylko przy POST
(tworzenie użytkownika). Logować każde użycie tokenu.

---

### M5 — Security log tylko w Redis
**Plik:** `src/services/securityLog.js`

Zdarzenia bezpieczeństwa są wyłącznie w Redis ZSET i Pub/Sub. Przy:
- `FLUSHALL` / `FLUSHDB` — całkowita utrata logów bezpieczeństwa
- Kompromitacji Redis — atakujący może wyczyścić dowody swojej aktywności
- Awarii Redis przed zapisem — zdarzenie utracone cicho

Atakujący z dostępem do Redis może usunąć wszystkie ślady przed wykryciem.

**Fix:** Dual-write: Redis (real-time) + append-only plik (persystentny).
Lub forward przez Pub/Sub consumer do zewnętrznego SIEM przy starcie serwera.

---

### M6 — `client_secret` w POST body
**Plik:** `src/routes/oidc.js` — endpoint `/token`

OAuth 2.0 RFC 6749 §2.3.1 zaleca HTTP Basic Auth dla `client_secret`.
Przekazanie w ciele żądania powoduje, że sekret pojawia się w:
- Access logach (jeśli logowane body)
- Stack traces przy błędach
- Repozytoriach z request examples (api.http)

**Fix:** Obsługiwać HTTP Basic Auth jako preferowaną metodę, body jako fallback.

---

### M7 — CSP: `script-src 'unsafe-inline'`
**Plik:** `src/app.js`

`'unsafe-inline'` zezwala na wykonanie inline skryptów. Jeśli atakujący wstrzyknie
kod HTML przez niezabezpieczony punkt (np. `user.name` lub `user.username` renderowany
bez escape'owania w `signin.html`), XSS ma dostęp do:
- Tokenów HSM w pamięci JS (`useToken`, `session.password`)
- `window.location.hash` (enrollment token)
- Możliwości wykonania `exdsaSign` — podpisanie złośliwego JWT

CSP chroni przez `connect-src` — XSS nie wyśle danych do zewnętrznego serwera
(tylko do `*.ence.do` i `api.encedo.com`). Ale lokalny atak (token theft, HSM signing) nadal możliwy.

**Fix (docelowy):** Wyekstrahować inline `<script type="module">` z `signin.html`
i `enrollment.html` do oddzielnych plików `.js`. Usunąć `'unsafe-inline'`.
To jest pełna ochrona przed XSS — nawet wstrzyknięty `<script>` nie wykona się.

---

## LOW

### L1 — CORS `*` na `/token` — code theft + known secret = token theft
**Plik:** `src/app.js:59`

`/token` endpoint ma `CORS: *`. Klient bez PKCE używa `client_secret`.
Jeśli atakujący zna `client_secret` (np. skradziony z konfiguracji RP)
i przechwyci kod autoryzacji (np. przez phishing redirect_uri), może wymienić
go na tokeny z dowolnej strony w przeglądarce.

**Łagodzący:** Wymaga jednocześnie: skradzionego `client_secret` + skradzionego `code`.
Przy PKCE: kod sam w sobie bezużyteczny.

**Fix:** Wymuszać PKCE dla wszystkich nowych klientów webowych. Rozważyć usunięcie
`client_secret` jako metody auth dla klientów public (SPA).

---

### L2 — Admin rate limit per-IP, efektywnie nieograniczony
**Plik:** `src/app.js:98`

Rate limit admina: 60 req/min per IP. Bez `ADMIN_ALLOWED_IPS` — 60 IP × 60/min =
3600 prób na minutę z sieci. Przy braku network restriction: rozproszony atak realny.

---

### L3 — PKCE opcjonalne per klient
Klienci mogą działać bez PKCE. Authorization code interception attack możliwy
dla klientów bez PKCE (wymagane jednoczesne przechwycenie code + posiadanie secret).

---

### L4 — JWKS: brak server-side cache
`GET /jwks.json` ładuje wszystkich userów z Redis przy każdym żądaniu.
`Cache-Control: max-age=3600` pomaga zewnętrznym klientom, ale sam serwer
odpytuje Redis za każdym razem. Może być używany jako DoS vector (JWKS flood).

---

### L5 — Brak `/token/revoke` (RFC 7009)
Klient (RP) nie może aktywnie unieważnić access token po stronie IdP.
Przy kompromitacji RP (np. wyciek cookie store), wszystkie tokeny ważne do expiry.

---

## Co jest zrobione dobrze

| Mechanizm | Opis |
|-----------|------|
| Ed25519 w HSM | Klucz prywatny NIGDY nie opuszcza HSM. Podpis niemożliwy bez fizycznego dostępu |
| `kid` anchored w sesji | Frontend nie może podmienić klucza między login a confirm |
| pubkey zawsze z Redis | Weryfikacja podpisu używa klucza z Redis, nie z requestu |
| `timingSafeEqual` | client_secret i ADMIN_SECRET — ochrona przed timing attacks |
| PKCE S256 | Zaimplementowane i walidowane per klient |
| Enrollment challenge-response | Proof-of-possession klucza przy rejestracji |
| `getDel` | Jednorazowe tokeny i kody — anti-replay |
| Unified error message | Brak user enumeration przez /authorize/login |
| URL fragment dla enrollment | Token poza logami serwera i Referer |
| Rate limiting | login 20/min, confirm 10/min, token 20/min, enroll 10+5/min |
| Security logging | Redis Pub/Sub + ZSET, 14 typów zdarzeń |
| CSP `connect-src` | Ogranicza exfiltrację danych przez XSS do znanych domen |
| CORS zawężone | Tylko OIDC protocol endpoints (`/jwks`, `/token`, `/userinfo`, `/.well-known`) |
| Access token revocation | `user_tokens:{sub}` SET — kasowane przy DELETE usera |
| `jti` w ID tokenach | Fundament pod przyszłą revocation list |
| Body limit 32kb | Ochrona przed oversized payloads |
| Security headers | CSP, HSTS (prod), X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| HTTPS wymuszone na hsm_url | `httpsOnly: true` — RFC1918 dozwolone (PPA w LAN) |

---

## Priorytety do implementacji

1. **C1** — Atestacja: wdrożyć POST do api.encedo.com (jutro)
2. **M7** — Wyekstrahować inline JS → usunąć `'unsafe-inline'` z CSP
3. **H3** — Username index w Redis → O(1) lookup
4. **M3** — OIDC logout endpoint
5. **H4** — ID token revocation: krótki TTL (5min) lub introspection endpoint
6. **M2** — Usunąć JWT payload z logów prod
7. **M4** — Ukryć `enrollment_token` w GET
8. **M1** — Naprawić TTL logikę `user_tokens:{sub}`
