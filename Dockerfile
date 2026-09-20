FROM node:22-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src/           ./src/
COPY index.html     index.js     \
     landing.html   landing.js   \
     signin.html    signin.js    hsm-common.js \
     enrollment.html enrollment.js \
     admin-panel.html admin-panel.js \
     signup.html     signup.js    \
     signup-client.html signup-client.js \
     verify-email.html verify-email.js \
     logo.png        favicon.ico ./
# HEM SDK: pre-built browser bundle from the hem-sdk-js git submodule
# (clone with --recurse-submodules, or the COPY fails on an empty directory).
COPY hem-sdk-js/hem-sdk.browser.js hem-sdk-js/hem-sdk.browser.js.map ./hem-sdk-js/

ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

# The app needs no privileges: it listens on an unprivileged port and only reads
# its own files (root-owned, world-readable). Drop to the image's built-in user.
USER node

EXPOSE 3000
# /health answers 503 when Redis is unreachable, so `docker ps` shows the
# container unhealthy instead of a green process that can serve nothing.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/app.js"]
