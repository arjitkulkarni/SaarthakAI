# Satark AI - container image for Google Cloud Run
FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=8080

WORKDIR /app

# No third-party npm dependencies: the app only uses Node.js built-ins.
COPY package.json ./
COPY server.js ./
COPY src ./src
COPY public ./public

# Run as the unprivileged "node" user
USER node

EXPOSE 8080
CMD ["node", "server.js"]
