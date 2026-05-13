FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=builder /app/dist ./dist
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/healthz || exit 1
ENTRYPOINT ["node", "dist/index.js"]
