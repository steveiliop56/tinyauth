# Site builder
FROM oven/bun:1.1.45-alpine AS site-builder

WORKDIR /site

COPY ./site/package.json ./
COPY ./site/bun.lockb ./

RUN bun install

COPY ./site/public ./public
COPY ./site/src ./src
COPY ./site/eslint.config.js ./
COPY ./site/index.html ./
COPY ./site/tsconfig.json ./
COPY ./site/tsconfig.app.json ./
COPY ./site/tsconfig.node.json ./
COPY ./site/vite.config.ts ./
COPY ./site/postcss.config.cjs ./

RUN bun run build

# Builder
FROM golang:1.23-alpine3.21 AS builder

WORKDIR /tinyauth

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY ./main.go ./
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY --from=site-builder /site/dist ./internal/assets/dist

RUN go build

# Runner
FROM alpine:3.21 AS runner

WORKDIR /tinyauth

COPY --from=builder /tinyauth/tinyauth ./

EXPOSE 3000

ENTRYPOINT ["./tinyauth"]