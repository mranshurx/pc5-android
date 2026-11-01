FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/package.json ./backend/package.json
RUN cd backend && npm install --omit=dev

COPY backend ./backend
COPY frontend ./frontend
COPY relay.sh ./relay.sh
RUN chmod +x ./relay.sh

ENV PORT=3000
EXPOSE 3000
CMD ["./relay.sh"]
