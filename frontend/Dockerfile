# Build stage
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# `npm ci` when a lockfile is present (reproducible), else fall back.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

# Serve stage
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx-security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:80/ || exit 1

# Step 31: nginx master runs as root only to bind :80 and drops
# privileges for its workers (see the comment in docker-compose.yml for
# why capabilities are therefore not dropped here). The cache and temp
# paths are declared so the intent is explicit if a read-only root
# filesystem is enabled later.
STOPSIGNAL SIGQUIT
