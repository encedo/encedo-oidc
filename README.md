# Encedo OIDC Provider

HSM-anchored OpenID Connect Identity Provider. Private keys **never leave the HSM**. Every token signing requires physical confirmation on a mobile device or a passphrase.

- **Protocol:** OpenID Connect Core 1.0 + PKCE (RFC 7636)
- **Signing:** Ed25519 via Encedo HEM hardware
- **Storage:** Redis only — no SQL database
- **Runtime:** Node.js v22 ESM, Express 4

---

## Quick Start (local development)

### Prerequisites

- Node.js v22+
- Redis 7+
- An Encedo PPA or EPA device (or `my.ence.do` USB key)

```
git clone https://github.com/encedo/encedo-oidc.git
cd encedo-oidc
npm install

cp .env.example .env
# Edit .env -- set ADMIN_SECRET and ISSUER=http://localhost:3000

sudo systemctl start redis

npm run dev    # hot reload
# or
npm start
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP port |
| `ISSUER` | — | Public OIDC issuer URL (e.g. `https://auth.example.com`) |
| `ADMIN_SECRET` | — | Bearer token for admin API — must be set |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection string (`rediss://` for TLS) |
| `NODE_ENV` | `development` | Set to `production` to enable HSTS |
| `ADMIN_ALLOWED_IPS` | `127.0.0.1,::1` | Comma-separated IPs/CIDRs allowed to reach admin API |
| `TRUST_PROXY` | — | Set to `1` when behind nginx/Caddy (enables `req.ip` from `X-Forwarded-For`) |
| `CSP_CONNECT_EXTRA` | — | Extra space-separated origins for CSP `connect-src` (EPA custom domains) |

---

## Production Deployment — Single Instance

One OIDC provider for one organization. Redis and Node.js run directly on the host, managed by systemd.

### Step-by-step on Ubuntu 24.04

#### 1. Install Node.js 22, Redis, and git

```
sudo apt install -y git
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs redis-server
sudo systemctl enable --now redis-server
```

#### 2. Clone the repo and install dependencies

```
sudo useradd -r -s /usr/sbin/nologin -d /opt/encedo-oidc encedo
sudo mkdir -p /opt/encedo-oidc
sudo chown encedo:encedo /opt/encedo-oidc

sudo -u encedo git clone https://github.com/encedo/encedo-oidc.git /opt/encedo-oidc
cd /opt/encedo-oidc
sudo -u encedo npm ci --omit=dev
```

#### 3. Configure

```
sudo -u encedo cp /opt/encedo-oidc/.env.example /opt/encedo-oidc/.env
sudo chmod 600 /opt/encedo-oidc/.env
sudo nano /opt/encedo-oidc/.env
```

Minimum required settings:

```ini
PORT=3000
NODE_ENV=production
ISSUER=https://auth.example.com
ADMIN_SECRET=replace-with-a-strong-random-secret
ADMIN_ALLOWED_IPS=127.0.0.1,::1,YOUR.ADMIN.IP
TRUST_PROXY=1
```

#### 4. Point DNS to your server

Add an A record in your DNS provider:

```
auth.example.com  A  <your-server-public-ip>
```

Wait for propagation before the next step (`dig auth.example.com` should return your IP).

#### 5. Install nginx

```
sudo apt install -y nginx
sudo systemctl enable --now nginx
```

#### 6. TLS certificate (Let's Encrypt)

nginx is running, so use the webroot method — no downtime:

```
sudo apt install -y certbot
sudo mkdir -p /var/www/certbot
sudo certbot certonly --webroot -w /var/www/certbot -d auth.example.com
```

certbot's systemd timer renews the cert automatically. Add a deploy hook so nginx reloads after each renewal:

```
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'EOF'
#!/bin/sh
systemctl reload nginx
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

#### 7. Configure nginx

Create `/etc/nginx/sites-available/encedo-oidc` with the following content:

```nginx
upstream oidc_backend {
    server 127.0.0.1:3000;
    keepalive 16;
}

limit_req_zone $binary_remote_addr zone=oidc_login:10m   rate=5r/m;
limit_req_zone $binary_remote_addr zone=oidc_token:10m   rate=10r/m;
limit_req_zone $binary_remote_addr zone=oidc_general:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=oidc_jwks:10m    rate=60r/m;

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;

    location = /authorize/login {
        limit_req zone=oidc_login burst=3 nodelay;
        proxy_pass http://oidc_backend;
        include /etc/nginx/proxy_params;
    }
    location = /token {
        limit_req zone=oidc_token burst=5 nodelay;
        proxy_pass http://oidc_backend;
        include /etc/nginx/proxy_params;
    }
    location = /jwks.json {
        limit_req zone=oidc_jwks burst=20 nodelay;
        proxy_pass http://oidc_backend;
        include /etc/nginx/proxy_params;
    }
    location /admin {
        allow 10.0.0.0/8;
        allow 127.0.0.1;
        deny  all;
        limit_req zone=oidc_general burst=10 nodelay;
        proxy_pass http://oidc_backend;
        include /etc/nginx/proxy_params;
    }
    location / {
        limit_req zone=oidc_general burst=20 nodelay;
        proxy_pass http://oidc_backend;
        include /etc/nginx/proxy_params;
    }
}

# HTTP: ACME webroot for cert renewal + redirect to HTTPS
server {
    listen 80;
    server_name auth.example.com;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}
```

```
sudo nano /etc/nginx/sites-available/encedo-oidc   # paste the config above
sudo ln -s /etc/nginx/sites-available/encedo-oidc /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

#### 8. systemd service

```
sudo tee /etc/systemd/system/encedo-oidc.service << 'EOF'
[Unit]
Description=Encedo OIDC Provider
After=network.target redis.service

[Service]
Type=simple
User=encedo
WorkingDirectory=/opt/encedo-oidc
EnvironmentFile=/opt/encedo-oidc/.env
ExecStart=/usr/bin/node src/app.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now encedo-oidc
```

#### 9. Verify

```
sudo systemctl status encedo-oidc
curl https://auth.example.com/.well-known/openid-configuration
```

The server is running. Continue to [First Steps After Startup](#first-steps-after-startup) to create your first client and user.

---

## Production Deployment — Multi-Tenant (Docker)

Run multiple independent organizations on one server. Each tenant gets its own OIDC container and Redis container, fully isolated. A shared nginx container sits in front and routes by subdomain. All tenant containers use one Docker image built once from this repo.

```
acme.oidc.encedo.com    ──┐
bigcorp.oidc.encedo.com ──┼── nginx ──► oidc-acme    ──► redis-acme
                          │         └─► oidc-bigcorp ──► redis-bigcorp
```

### Directory layout

```
/opt/encedo-oidc/
├── src/                        ← git clone of this repo (Docker build context)
├── nginx/
│   ├── docker-compose.yml      ← nginx container, started once, never changes
│   ├── nginx.conf              ← add one server block per tenant
│   └── proxy_params
└── tenants/
    ├── docker-compose.yml      ← template, identical for every tenant, never edit
    ├── acme/
    │   └── .env                ← only this file differs per tenant (chmod 600)
    └── bigcorp/
        └── .env
```

Redis data lives in named Docker volumes (`redis-{tenant}-data`) — survives container restarts and `docker compose down`.

### Step-by-step on Ubuntu 24.04

#### 1. Install Docker and git

```
sudo apt install -y git
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

#### 2. Point DNS to your server

Add a single wildcard A record in your DNS provider:

```
*.oidc.encedo.com  A  <server-ip>
```

This covers all current and future tenants — no DNS change needed when adding a new one. Wait for propagation (`dig acme.oidc.encedo.com` should return your IP).

> **Note:** a wildcard DNS A record and a wildcard TLS cert are independent. The `*` here just routes all subdomains to your server. TLS certs are still issued per subdomain via HTTP-01 — no DNS challenge needed.

#### 3. TLS certificates (Let's Encrypt)

Docker is not running yet, so port 80 is free for certbot's built-in web server:

```
sudo apt install -y certbot
sudo certbot certonly --standalone -d acme.oidc.encedo.com
sudo certbot certonly --standalone -d bigcorp.oidc.encedo.com
```

Certificates land in `/etc/letsencrypt/live/<domain>/`. They are bind-mounted into the nginx container. See [Cert renewal](#cert-renewal) for automated renewal setup.

#### 4. Create directory structure and shared Docker network

```
sudo mkdir -p /opt/encedo-oidc/nginx
sudo mkdir -p /opt/encedo-oidc/tenants/acme
sudo mkdir -p /opt/encedo-oidc/tenants/bigcorp
sudo chown -R $USER /opt/encedo-oidc

docker network create oidc-net
```

#### 5. Clone repo and build the OIDC image

```
git clone https://github.com/encedo/encedo-oidc.git /opt/encedo-oidc/src
docker build -t encedo-oidc:latest /opt/encedo-oidc/src
```

The image is built once and shared by all tenants. See [Updating](#updating) for how to deploy new releases.

#### 6. Create nginx/proxy_params

```
cat > /opt/encedo-oidc/nginx/proxy_params << 'EOF'
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_http_version 1.1;
proxy_set_header Connection "";
EOF
```

#### 7. Create nginx/nginx.conf

```nginx
# nginx/nginx.conf
events {}

http {
    limit_req_zone $binary_remote_addr zone=oidc_login:10m   rate=5r/m;
    limit_req_zone $binary_remote_addr zone=oidc_token:10m   rate=10r/m;
    limit_req_zone $binary_remote_addr zone=oidc_general:10m rate=30r/m;
    limit_req_zone $binary_remote_addr zone=oidc_jwks:10m    rate=60r/m;

    # HTTP: ACME webroot for renewal + redirect everything else to HTTPS
    server {
        listen 80;
        server_name ~^[^.]+\.oidc\.encedo\.com$;
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS — tenant: acme
    server {
        listen 443 ssl http2;
        server_name acme.oidc.encedo.com;
        ssl_certificate     /etc/letsencrypt/live/acme.oidc.encedo.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/acme.oidc.encedo.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers   ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;

        location = /authorize/login { limit_req zone=oidc_login    burst=3  nodelay; proxy_pass http://oidc-acme:3000; include /etc/nginx/proxy_params; }
        location = /token          { limit_req zone=oidc_token     burst=5  nodelay; proxy_pass http://oidc-acme:3000; include /etc/nginx/proxy_params; }
        location = /jwks.json      { limit_req zone=oidc_jwks      burst=20 nodelay; proxy_pass http://oidc-acme:3000; include /etc/nginx/proxy_params; }
        location /admin {
            allow 10.0.0.0/8; allow 127.0.0.1; deny all;
            limit_req zone=oidc_general burst=10 nodelay;
            proxy_pass http://oidc-acme:3000; include /etc/nginx/proxy_params;
        }
        location / { limit_req zone=oidc_general burst=20 nodelay; proxy_pass http://oidc-acme:3000; include /etc/nginx/proxy_params; }
    }

    # HTTPS — tenant: bigcorp
    server {
        listen 443 ssl http2;
        server_name bigcorp.oidc.encedo.com;
        ssl_certificate     /etc/letsencrypt/live/bigcorp.oidc.encedo.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/bigcorp.oidc.encedo.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers   ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;

        location = /authorize/login { limit_req zone=oidc_login    burst=3  nodelay; proxy_pass http://oidc-bigcorp:3000; include /etc/nginx/proxy_params; }
        location = /token          { limit_req zone=oidc_token     burst=5  nodelay; proxy_pass http://oidc-bigcorp:3000; include /etc/nginx/proxy_params; }
        location = /jwks.json      { limit_req zone=oidc_jwks      burst=20 nodelay; proxy_pass http://oidc-bigcorp:3000; include /etc/nginx/proxy_params; }
        location /admin {
            allow 10.0.0.0/8; allow 127.0.0.1; deny all;
            limit_req zone=oidc_general burst=10 nodelay;
            proxy_pass http://oidc-bigcorp:3000; include /etc/nginx/proxy_params;
        }
        location / { limit_req zone=oidc_general burst=20 nodelay; proxy_pass http://oidc-bigcorp:3000; include /etc/nginx/proxy_params; }
    }

    # Add a new server block for each additional tenant (copy either block above).
}
```

```
nano /opt/encedo-oidc/nginx/nginx.conf   # paste the config above
```

#### 8. Create nginx/docker-compose.yml

```
cat > /opt/encedo-oidc/nginx/docker-compose.yml << 'EOF'
services:
  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./proxy_params:/etc/nginx/proxy_params:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /var/www/certbot:/var/www/certbot:ro
    networks:
      - oidc-net

networks:
  oidc-net:
    external: true
EOF
```

#### 9. Copy the tenant template

The repo ships a ready-made `tenants/docker-compose.yml`. Copy it into each tenant folder — **it is identical for every tenant and never needs editing**. Container names are derived from the `TENANT` variable in `.env`:

```
cp /opt/encedo-oidc/src/tenants/docker-compose.yml /opt/encedo-oidc/tenants/acme/docker-compose.yml
cp /opt/encedo-oidc/src/tenants/docker-compose.yml /opt/encedo-oidc/tenants/bigcorp/docker-compose.yml
```

#### 10. Create tenant .env files

```
cat > /opt/encedo-oidc/tenants/acme/.env << 'EOF'
TENANT=acme
PORT=3000
NODE_ENV=production
ISSUER=https://acme.oidc.encedo.com
REDIS_URL=redis://redis-acme:6379
ADMIN_SECRET=replace-with-strong-secret-acme
ADMIN_ALLOWED_IPS=127.0.0.1,::1,YOUR.ADMIN.IP.HERE
TRUST_PROXY=1
EOF
chmod 600 /opt/encedo-oidc/tenants/acme/.env

cat > /opt/encedo-oidc/tenants/bigcorp/.env << 'EOF'
TENANT=bigcorp
PORT=3000
NODE_ENV=production
ISSUER=https://bigcorp.oidc.encedo.com
REDIS_URL=redis://redis-bigcorp:6379
ADMIN_SECRET=replace-with-strong-secret-bigcorp
ADMIN_ALLOWED_IPS=127.0.0.1,::1,YOUR.ADMIN.IP.HERE
TRUST_PROXY=1
EOF
chmod 600 /opt/encedo-oidc/tenants/bigcorp/.env
```

Edit both files — set real secrets and your admin IP:

```
nano /opt/encedo-oidc/tenants/acme/.env
nano /opt/encedo-oidc/tenants/bigcorp/.env
```

#### 11. Start nginx

```
cd /opt/encedo-oidc/nginx && docker compose up -d
```

#### 12. Start tenants

```
cd /opt/encedo-oidc/tenants/acme    && docker compose up -d
cd /opt/encedo-oidc/tenants/bigcorp && docker compose up -d
```

#### 13. Verify

```
docker ps
curl https://acme.oidc.encedo.com/.well-known/openid-configuration
curl https://bigcorp.oidc.encedo.com/.well-known/openid-configuration
```

All containers should be running. Continue to [First Steps After Startup](#first-steps-after-startup).

### Adding a new tenant

DNS is already covered by the wildcard A record — no changes needed there.

1. Get a TLS cert (nginx is running and serving the webroot):
   ```
   sudo certbot certonly --webroot -w /var/www/certbot -d {tenant}.oidc.encedo.com
   ```
2. Create the tenant folder and copy the template:
   ```
   mkdir -p /opt/encedo-oidc/tenants/{tenant}
   cp /opt/encedo-oidc/src/tenants/docker-compose.yml /opt/encedo-oidc/tenants/{tenant}/
   ```
3. Create `.env` (copy from an existing tenant, change `TENANT`, `ISSUER`, `ADMIN_SECRET`):
   ```
   cp /opt/encedo-oidc/tenants/acme/.env /opt/encedo-oidc/tenants/{tenant}/.env
   chmod 600 /opt/encedo-oidc/tenants/{tenant}/.env
   nano /opt/encedo-oidc/tenants/{tenant}/.env
   ```
4. Start the tenant:
   ```
   cd /opt/encedo-oidc/tenants/{tenant} && docker compose up -d
   ```
5. Add a server block to `nginx/nginx.conf` (copy an existing HTTPS block, update `server_name`, cert paths, and `proxy_pass`)
6. Reload nginx:
   ```
   docker compose -f /opt/encedo-oidc/nginx/docker-compose.yml exec nginx nginx -s reload
   ```

No restart of existing tenants required.

### Updating

When a new release is available:

```
# 1. Pull latest source
cd /opt/encedo-oidc/src && git pull

# 2. Build new image — once, shared by all tenants
docker build -t encedo-oidc:latest /opt/encedo-oidc/src

# 3. Restart each tenant's OIDC container (Redis is untouched, data is safe)
for dir in /opt/encedo-oidc/tenants/*/; do
  [ -f "$dir/docker-compose.yml" ] && docker compose -f "$dir/docker-compose.yml" up -d --no-deps oidc
done
```

### Cert renewal

nginx serves `/.well-known/acme-challenge/` from `/var/www/certbot`. certbot renews certs without stopping nginx:

```
sudo certbot renew --webroot -w /var/www/certbot
```

Create a deploy hook so nginx reloads automatically after every renewal:

```
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'EOF'
#!/bin/sh
docker compose -f /opt/encedo-oidc/nginx/docker-compose.yml exec nginx nginx -s reload
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

certbot's systemd timer runs `certbot renew` twice a day — no cron needed. Let's Encrypt sends email reminders at 30/7/1 days before expiry.

> **Note:** the first cert per tenant was issued with `--standalone`. Switch to webroot once so auto-renewal works:
> ```
> sudo certbot certonly --webroot -w /var/www/certbot -d acme.oidc.encedo.com --force-renewal
> sudo certbot certonly --webroot -w /var/www/certbot -d bigcorp.oidc.encedo.com --force-renewal
> ```
> After this, all renewals are fully automatic.

---

## First Steps After Startup

The server starts empty — no users, no OIDC clients. Follow these steps to get your first login working.

> **Admin API is network-restricted.** nginx only allows `/admin` from `10.0.0.0/8` and `127.0.0.1`. Run the commands below from the server itself over SSH, or temporarily add your IP to the nginx allow block.

**Single instance — SSH into the server, then:**

```
sudo apt install -y jq
export ADMIN_SECRET=your-admin-secret-here
export BASE=http://127.0.0.1:3000   # bypass nginx, hit the app directly
```

**Multi-tenant (Docker) — run inside the tenant container:**

```
docker exec -it oidc-acme sh

# Inside the container:
apk add --no-cache curl jq
export ADMIN_SECRET=your-admin-secret-here
export BASE=http://localhost:3000
```

### 1. Create an OIDC client

```
curl -s -X POST $BASE/admin/clients \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "scopes": ["openid", "profile", "email"],
    "pkce": true
  }' | tee client.json
```

Note the `client_id` and `client_secret` from the response — configure these in your RP (e.g. Nextcloud).

### 2. Create a user

```
curl -s -X POST $BASE/admin/users \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "name": "Alice Smith",
    "email": "alice@example.com",
    "hsm_url": "https://alice.ence.do"
  }' | tee user.json
```

> `hsm_url` is the URL of the user's Encedo HSM. For `my.ence.do` cloud devices it is `https://<username>.ence.do`. For a local PPA/EPA device it is the local address shown in the HEM app (e.g. `http://192.168.1.50:2999`).

Note the `sub` (user ID) from the response.

### 3. Generate an enrollment link

```
SUB=$(jq -r .sub user.json)
curl -s -X POST $BASE/admin/users/$SUB/enrollment \
  -H "Authorization: Bearer $ADMIN_SECRET" | tee enrollment.json

jq -r .enrollment_url enrollment.json
```

Send the returned `enrollment_url` to the user. The link is valid for 24 hours.

### 4. Enroll the HSM key

The user opens the enrollment link in a browser **with their Encedo HSM connected**. The page will:

1. Connect to the HSM
2. Generate an Ed25519 key pair on the device
3. Sign a server-issued challenge (proof of key possession)
4. Fetch hardware attestation from the HSM
5. Submit the public key to the server

After enrollment the user can log in. Point their OIDC client at `https://auth.example.com/.well-known/openid-configuration`.

---

## OIDC Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | Discovery document |
| `GET` | `/jwks.json` | Public keys (Ed25519) |
| `GET` | `/authorize` | Start login flow — serves `signin.html` |
| `POST` | `/authorize/login` | Initiate signing session |
| `POST` | `/authorize/confirm` | Submit HSM signature, get auth code |
| `POST` | `/token` | Exchange code for tokens (PKCE) |
| `GET/POST` | `/userinfo` | Return claims for access token |
| `GET` | `/logout` | RP-initiated logout |
| `GET` | `/health` | Liveness check |

## Admin API

All `/admin/*` endpoints require `Authorization: Bearer <ADMIN_SECRET>` and are restricted to `ADMIN_ALLOWED_IPS`.

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/admin/users` | List / create users |
| `GET/PATCH/DELETE` | `/admin/users/:sub` | Read / update / delete user |
| `POST` | `/admin/users/:sub/enrollment` | Generate new enrollment link |
| `GET/POST` | `/admin/clients` | List / create OIDC clients |
| `GET/PATCH/DELETE` | `/admin/clients/:id` | Read / update / delete client |
| `POST` | `/admin/clients/:id/rotate-secret` | Rotate client secret |
| `GET` | `/admin/audit-log` | Security event log |

## Enrollment

New users receive a one-time enrollment link (24 h TTL). Opening it in a browser with an Encedo HSM connected:

1. Connects to HSM, generates Ed25519 key pair on the device
2. Signs a server-issued challenge (proof of key possession)
3. Fetches hardware attestation from HSM
4. Submits public key + attestation to `/enrollment/submit`

---

## User Lookup

`POST /authorize/login` accepts either:
- `sub` — direct Redis O(1) lookup
- `username` — O(1) lookup via `username_index` hash

The `signin.html` Trusted App uses `sub` (embedded in the HSM key description as `btoa('ETSOIDC' + sub)`).
