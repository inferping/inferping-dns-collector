# SECURITY.md - inferping-dns-collector Security Architecture & Review Log

## 1. Security & Privacy Architecture

- **Single-Purpose Passive Design**: `inferping-dns-collector` contains zero active network probing, zero prompt/payload inspection, and zero third-party Go dependencies (`CGO_ENABLED=0` standard library only), enforced in CI by `TestZeroActiveProbingOrThirdPartyDependencies`.
- **On-Premise PII Stripping in RAM**: Raw log lines from DNS files, syslog, Loki, Splunk, HTTP HEC, and Kafka are scanned in memory for domain tokens against the allowlisted public FQDN map (`catalogue/ai-tools.json`) and immediately discarded. Client IP addresses, MAC addresses, usernames, and internal corporate domains (`.local`, `.internal`, `.corp`, `.lan`, RFC 1918 literals) are never stored or transmitted.
- **Encrypted Syslog (RFC 5425 TLS 1.2/1.3 & mTLS)**: `-syslog-tls-listen` enforces TLS 1.2+ AEAD cipher suites, 10-second handshake timeouts, 64 KiB RFC 6587 frame bounds, and optional mutual TLS client-certificate verification (`-syslog-tls-client-ca` -> `tls.RequireAndVerifyClientCert`).
- **Authenticated Bounded HTTP Sink**: `-http-listen` validates `Authorization: Bearer` / `Splunk` / `X-API-Key` tokens in constant time (`subtle.ConstantTimeCompare`) and bounds request bodies via `http.MaxBytesReader` (4 MiB compressed / 8 MiB gunzipped).
- **Container Hardening**: Packaged on `gcr.io/distroless/static-debian12:nonroot` (`uid=65532`) for `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true` execution.

## 2. Commit Security Notes

- **2026-11-25 (`v1.0.0`)**: Initial standalone release of `inferping-dns-collector` separated from `inferping-probe` so corporate AD, firewall, SIEM, and Works Council reviewers can deploy a dedicated zero-dependency, passive-only domain counter with RFC 5425 mTLS syslog, Windows AD DNS wire-label parsing, Loki/Splunk/HEC/Kafka connectors, 5m ETag catalogue sync, and lossless retry on transient OTLP HTTP errors.
