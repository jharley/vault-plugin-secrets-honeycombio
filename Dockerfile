FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o vault-plugin-secrets-honeycombio ./cmd/vault-plugin-secrets-honeycombio

FROM hashicorp/vault:1.21@sha256:4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569 AS vault
COPY --from=builder /build/vault-plugin-secrets-honeycombio /vault/plugins/vault-plugin-secrets-honeycombio

FROM openbao/openbao:2.5@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878 AS openbao
COPY --from=builder /build/vault-plugin-secrets-honeycombio /openbao/plugins/vault-plugin-secrets-honeycombio
