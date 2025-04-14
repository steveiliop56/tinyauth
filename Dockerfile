# Site builder
FROM oven/bun:1.1.45-alpine AS frontend-builder

WORKDIR /frontend

COPY ./frontend/package.json ./
COPY ./frontend/bun.lockb ./

RUN bun install

COPY ./frontend/public ./public
COPY ./frontend/src ./src
COPY ./frontend/eslint.config.js ./
COPY ./frontend/index.html ./
COPY ./frontend/tsconfig.json ./
COPY ./frontend/tsconfig.app.json ./
COPY ./frontend/tsconfig.node.json ./
COPY ./frontend/vite.config.ts ./
COPY ./frontend/postcss.config.cjs ./

RUN bun run build

# Builder
FROM golang:1.24-alpine3.21 AS builder

WORKDIR /tinyauth

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY ./main.go ./
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY --from=frontend-builder /frontend/dist ./internal/assets/dist

RUN CGO_ENABLED=0 go build -ldflags "-s -w"

# Runner
FROM alpine:3.21 AS runner

WORKDIR /tinyauth

RUN apk add --no-cache curl

COPY --from=builder /tinyauth/tinyauth ./

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s \
    CMD curl -f http://localhost:3000/api/healthcheck || exit 1

ENTRYPOINT ["./tinyauth"]