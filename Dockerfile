FROM golang:1.26.8-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o vault-plugin-secrets-honeycombio ./cmd/vault-plugin-secrets-honeycombio

FROM hashicorp/vault:2.1.0 AS vault
COPY --from=builder /build/vault-plugin-secrets-honeycombio /vault/plugins/vault-plugin-secrets-honeycombio

FROM openbao/openbao:2.6.2 AS openbao
COPY --from=builder /build/vault-plugin-secrets-honeycombio /openbao/plugins/vault-plugin-secrets-honeycombio
