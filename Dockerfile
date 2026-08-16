FROM golang:1.26.6-alpine@sha256:1b2cb58c3df8b93b8bcb5739778692c35e491087599139deb2c8c03567cbb03e AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o vault-plugin-secrets-honeycombio ./cmd/vault-plugin-secrets-honeycombio

FROM hashicorp/vault:2.0.4@sha256:5be49781ecf78bfe775c5309c6a4d9f4e9e040b6c885c99eb2b12fb69855e1a2 AS vault
COPY --from=builder /build/vault-plugin-secrets-honeycombio /vault/plugins/vault-plugin-secrets-honeycombio

FROM openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0 AS openbao
COPY --from=builder /build/vault-plugin-secrets-honeycombio /openbao/plugins/vault-plugin-secrets-honeycombio
