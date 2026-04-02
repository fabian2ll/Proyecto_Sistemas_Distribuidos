FROM node:22-alpine AS base
WORKDIR /app

# Stage: development
FROM base AS development
COPY package.json package-lock.json ./
RUN npm install
COPY . .
CMD ["npm", "run", "start:dev"]

# Stage: builder
FROM base AS builder
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
RUN npm ci --omit=dev

# Stage: staging
FROM base AS staging
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
ENV NODE_ENV=staging
CMD ["node", "dist/main"]

# Stage: production
FROM base AS production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
ENV NODE_ENV=production
CMD ["node", "dist/main"]
