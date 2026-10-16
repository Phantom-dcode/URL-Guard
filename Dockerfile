FROM node:20-alpine

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json* bun.lock* ./

# Install production dependencies
RUN npm install --omit=dev --legacy-peer-deps

# Copy application files and models
COPY server.js ./
COPY app/ ./app/
COPY models/ ./models/
COPY data/ ./data/
COPY src/ ./src/
COPY scripts/ ./scripts/

# Expose standard port
ENV PORT=3000
ENV HOST=0.0.0.0
ENV NODE_ENV=production

EXPOSE 3000

# Start server
CMD ["node", "server.js"]
