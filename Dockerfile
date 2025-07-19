FROM node:16.20.2-slim

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

# Build the application (no OpenSSL issues with Node 16)
RUN npm run build

# Expose port
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
