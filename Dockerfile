FROM node:20.18.0-slim

# Set the NODE_OPTIONS environment variable globally in the container
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

# Copy package files first for better Docker layer caching
COPY package-lock.json package.json ./

# Install npm dependencies
RUN npm ci --include=dev

# Copy all source code
COPY . .

# Build the application with the NODE_OPTIONS environment variable set
RUN npm run build

# Expose the port the app runs on
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
