FROM node:20-slim

WORKDIR /app

# System deps for Playwright (optional) and general use
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ffmpeg curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source
COPY src/ src/
COPY tsconfig.json ./

# Create data dirs
RUN mkdir -p data auth_store db /tmp/fortbot

# Non-root user
RUN groupadd -r fortbot && useradd -r -g fortbot fortbot \
    && chown -R fortbot:fortbot /app /tmp/fortbot
USER fortbot

CMD ["npx", "tsx", "src/main.ts"]
