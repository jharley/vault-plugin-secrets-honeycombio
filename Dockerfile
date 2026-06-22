FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o vault-plugin-secrets-honeycombio ./cmd/vault-plugin-secrets-honeycombio

FROM hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54 AS vault
COPY --from=builder /build/vault-plugin-secrets-honeycombio /vault/plugins/vault-plugin-secrets-honeycombio

FROM openbao/openbao:2.5.4@sha256:436eaf9778cad75507ff70ea26ace30dcbe15606e619ac3823495663d7f7c115 AS openbao
COPY --from=builder /build/vault-plugin-secrets-honeycombio /openbao/plugins/vault-plugin-secrets-honeycombio
