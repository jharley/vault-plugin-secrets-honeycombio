FROM golang:1.27rc2-alpine@sha256:dcbb18cc5fa1082364dc6aa95224b6b55429d09cbb9631a053d8064c1c367300 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o vault-plugin-secrets-honeycombio ./cmd/vault-plugin-secrets-honeycombio

FROM hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54 AS vault
COPY --from=builder /build/vault-plugin-secrets-honeycombio /vault/plugins/vault-plugin-secrets-honeycombio

FROM openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0 AS openbao
COPY --from=builder /build/vault-plugin-secrets-honeycombio /openbao/plugins/vault-plugin-secrets-honeycombio
