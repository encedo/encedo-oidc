FROM node:22-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src/           ./src/
COPY index.html     index.js     \
     landing.html   landing.js   \
     signin.html    signin.js    \
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

EXPOSE 3000
CMD ["node", "src/app.js"]
