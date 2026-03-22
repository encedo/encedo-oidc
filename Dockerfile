FROM node:22-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src/           ./src/
COPY signin.html    signin.js    \
     enrollment.html enrollment.js \
     admin-panel.html admin-panel.js \
     hem-sdk.js      logo.png    ./

ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

EXPOSE 3000
CMD ["node", "src/app.js"]
