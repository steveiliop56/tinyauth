# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf
# Site builder
FROM oven/bun:1.2-alpine@sha256:0841c588f6304300baf1d395ae339ce09a6e18c4b6a7cdd4fddcbdb87a2f096a AS frontend-builder

WORKDIR /frontend

COPY ./frontend/package.json ./
COPY ./frontend/bun.lock ./

RUN bun install

COPY ./frontend/public ./public
COPY ./frontend/src ./src
COPY ./frontend/eslint.config.js ./
COPY ./frontend/index.html ./
COPY ./frontend/tsconfig.json ./
COPY ./frontend/tsconfig.app.json ./
COPY ./frontend/tsconfig.node.json ./
COPY ./frontend/vite.config.ts ./

RUN bun run build

# Builder
FROM golang:1.25-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS builder

ARG VERSION
ARG COMMIT_HASH
ARG BUILD_TIMESTAMP

WORKDIR /tinyauth

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY ./main.go ./
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY --from=frontend-builder /frontend/dist ./internal/assets/dist

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-s -w -X tinyauth/internal/config.Version=${VERSION} -X tinyauth/internal/config.CommitHash=${COMMIT_HASH} -X tinyauth/internal/config.BuildTimestamp=${BUILD_TIMESTAMP}"

# compress the binary with upx
RUN apk add upx
RUN upx --best --lzma tinyauth

# Runner
FROM chainguard/static:latest@sha256:b2e1c3d3627093e54f6805823e73edd17ab93d6c7202e672988080c863e0412b AS runner

COPY --from=builder /tinyauth/tinyauth /usr/local/bin/tinyauth

EXPOSE 3000

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/tinyauth"]
