FROM node:18-alpine

# The API server does not run scans itself (dedicated worker containers do),
# so no scanner CLIs are installed. The custom scanner runs in the worker image.
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --production

# Copy source
COPY src/ ./src/

# Create directories
RUN mkdir -p logs reports

# Run as non-root
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 5000

CMD ["node", "src/app.js"]
