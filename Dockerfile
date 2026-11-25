FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY catalogue ./catalogue
COPY cmd ./cmd
ARG VERSION=1.0.0
RUN CLEAN_VER="${VERSION#v}" && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${CLEAN_VER}" -o /out/inferping-dns-collector ./cmd/inferping-dns-collector

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/inferping/inferping-dns-collector"
LABEL org.opencontainers.image.description="Zero-PII OpenTelemetry domain counter: aggregates DNS, RFC 5425 TLS Syslog, Loki, Splunk, and Kafka locally in RAM (0 client IPs stored) and exports 60s AI tool hit counts"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/inferping-dns-collector /usr/local/bin/inferping-dns-collector
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/inferping-dns-collector"]
