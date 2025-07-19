FROM node:20.18.0-slim

# Set the NODE_OPTIONS environment variable globally
ENV NODE_OPTIONS="--openssl-legacy-provider"

WORKDIR /app

# Install system dependencies
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
    build-essential \
    node-gyp \
    pkg-config \
    python-is-python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package-lock.json package.json ./

# Install npm dependencies
RUN npm ci --include=dev

# Copy source code
COPY . .

# CRITICAL FIX: Explicitly set NODE_OPTIONS in the RUN command
RUN NODE_OPTIONS="--openssl-legacy-provider" npm run build

# Expose port
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
