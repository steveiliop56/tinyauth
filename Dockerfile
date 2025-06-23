# Site builder
FROM oven/bun:1.2.17-alpine AS frontend-builder

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
FROM golang:1.24-alpine3.21 AS builder

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

RUN CGO_ENABLED=0 go build -ldflags "-s -w -X tinyauth/internal/constants.Version=${VERSION} -X tinyauth/internal/constants.CommitHash=${COMMIT_HASH} -X tinyauth/internal/constants.BuildTimestamp=${BUILD_TIMESTAMP}" 
 
# Runner
FROM alpine:3.22 AS runner

WORKDIR /tinyauth

RUN apk add --no-cache curl

COPY --from=builder /tinyauth/tinyauth ./

EXPOSE 3000

ENTRYPOINT ["./tinyauth"]