# Multi-stage Docker build for RedOS Security Platform
# Ensures reproducible production deployments

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source code
COPY src/ ./src/
COPY platform/ ./platform/

# Build TypeScript
RUN npx tsc

# Stage 2: Production
FROM node:20-alpine AS production

WORKDIR /app

# Install only production dependencies
COPY package.json ./
RUN npm ci --only=production

# Copy built code from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/platform/platform ./platform/platform

# Set non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start the server
CMD ["node", "dist/api.js"]