# Arguments
ARG VERSION
ARG COMMIT_HASH
ARG BUILD_TIMESTAMP

# Site builder
FROM oven/bun:1.2.12-alpine AS frontend-builder

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

RUN go build -ldflags "-s -w -X tinyauth/internal/constants.Version=${VERSION} -X tinyauth/internal/constants.CommitHash=${COMMIT_HASH} -X tinyauth/internal/constants.BuildTimestamp=${BUILD_TIMESTAMP}" 
 
# Runner
FROM alpine:3.21 AS runner

WORKDIR /tinyauth

RUN apk add --no-cache curl

COPY --from=builder /tinyauth/tinyauth ./

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s \
    CMD curl -f http://localhost:3000/api/healthcheck || exit 1

ENTRYPOINT ["./tinyauth"]