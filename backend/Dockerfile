FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM node:18-alpine AS production
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/node_modules/.bin /app/node_modules/.bin
COPY src ./src
EXPOSE 4000
CMD ["node", "src/app.js"]
