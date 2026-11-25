# <img src="./logo.svg" width="28" height="28" align="top" alt="InferPing" /> inferping-dns-collector

[![Release](https://img.shields.io/github/v/release/inferping/inferping-dns-collector?color=0EA5E9&label=release)](https://github.com/inferping/inferping-dns-collector/releases)
[![GHCR Container](https://img.shields.io/badge/ghcr.io-inferping%2Finferping--dns--collector-38BDF8)](https://github.com/inferping/inferping-dns-collector/pkgs/container/inferping-dns-collector)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-34D399)](./LICENSE)

Zero-PII OpenTelemetry domain counter for corporate Shadow-AI governance. Aggregates DNS query logs, RFC 5425 encrypted TLS/mTLS syslog, Grafana Loki, Splunk, HTTP HEC, and Kafka streams locally in RAM, strips all client IP addresses and usernames immediately, and exports 60-second organization-wide AI tool hit counts (`inferping.ai.discovery.hits`) via standard **OpenTelemetry (`OTLP/HTTP`)**.

Built in the EU for **[InferPing Governance](https://inferping.eu)** and designed specifically to pass **CISO, Active Directory / Firewall Admin, DPO (`GDPR` / `AVG` / `DSGVO`), and European Works Council (`OR` / `Betriebsrat` / `CSE`)** security review in minutes.

---

## Security & Privacy Guarantees (5-Minute CISO / DPO Audit)

- **Strictly passive domain counting**: Contains **zero** active network probing code, **zero** payload or prompt inspection, **zero** TLS interception, and **zero** endpoint/browser agents.
- **Zero third-party Go dependencies**: [`go.mod`](./go.mod) uses exclusively the Go standard library (`CGO_ENABLED=0`). The entire codebase is ~900 lines of plain Go (`catalogue/` + `cmd/inferping-dns-collector/`), auditable end-to-end in 5 minutes.
- **Zero PII leaves your network**: Client IP addresses, MAC addresses, hostnames, and log lines are discarded in local RAM immediately after `O(1)` domain-suffix matching against [`catalogue/ai-tools.json`](./catalogue/ai-tools.json) (`70` AI services / `187` domains). Only integer counters (`{"ai.tool.id": "deepseek-chat", "hits": 14}`) are flushed every 60 seconds.
- **Distroless non-root container**: Runs as `uid=65532` (`nonroot`) with `--read-only`, `--cap-drop=ALL`, `no-new-privileges:true`, and `< 25 MiB` RAM.
- **100% airgapped capable (`-airgapped`)**: Ships with all `187` AI domains compiled into the static binary and can push to an internal OpenTelemetry Collector (`-push-url=http://otelcol.internal:4318/v1/metrics`) with zero internet access.

---

## Supported Log & SIEM Sources

1. **Read-Only DNS Log File (`-dns-log`)**:
   - Bind9 (`named`), Unbound, CoreDNS, dnsmasq, Pi-hole, AdGuard Home, and **Microsoft Windows Server Active Directory DNS** (including native `(4)chat(8)deepseek(3)com(0)` wire-label debug logs and `logrotate` head-hash tracking).
2. **Encrypted Syslog over TLS 1.2 / 1.3 & Mutual TLS (`-syslog-tls-listen`)**:
   - RFC 5425 TLS listener (`0.0.0.0:6514`) with optional client-CA verification (`-syslog-tls-client-ca`) and native **RFC 6587 octet-counted** + newline framing for FortiGate, Palo Alto, OPNsense, Cisco, Infoblox, `rsyslog`, and `syslog-ng`.
3. **Plain Local / In-Cluster UDP & TCP Syslog (`-syslog-listen`)**:
   - Zero-disk listener (`0.0.0.0:5514`) for Kubernetes CoreDNS or loopback syslog forwarding.
4. **Grafana Loki (`-loki-url`, `-loki-query`)**:
   - Queries `/loki/api/v1/query_range` every 60s (`INFERPING_SOURCE_AUTH` Bearer/Basic token, optional `-loki-org-id`) with zero changes to DNS servers or firewalls.
5. **Splunk REST Export (`-splunk-url`, `-splunk-query`)**:
   - Streams bounded 60s searches from `/services/search/jobs/export` (`INFERPING_SOURCE_AUTH`) and discards `_raw` events in memory.
6. **Universal HTTP Log Sink (`-http-listen`)**:
   - Authenticated local receiver (`INFERPING_HTTP_INGEST_TOKEN`) compatible with **Splunk HEC** (`/services/collector/event`), **Grafana Loki / Alloy Push** (`/loki/api/v1/push`), and **Vector / Cribl / Fluent Bit / Cloudflare Logpush** (`/ingest`, NDJSON/gzip).
7. **Apache Kafka / Redpanda (`-kafka-brokers`, `-kafka-topic`)**:
   - Zero-dependency partition tailer (`TCP`, `-kafka-tls`, and `INFERPING_KAFKA_SASL="user:pass"`). Tails latest partition offsets directly without registering or altering broker consumer groups.

---

## Quickstart

### 1. Docker: Encrypted RFC 5425 TLS / mTLS Syslog (FortiGate, Palo Alto, Infoblox, rsyslog)

```bash
docker run -d --name inferping-dns-collector --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  -p 6514:6514/tcp -v /etc/inferping/certs:/certs:ro \
  -e INFERPING_API_KEY="inf_live_your_workspace_key" \
  ghcr.io/inferping/inferping-dns-collector:latest \
  -syslog-tls-listen=0.0.0.0:6514 \
  -syslog-tls-cert=/certs/server.crt \
  -syslog-tls-key=/certs/server.key \
  -syslog-tls-client-ca=/certs/corp-ca.crt \
  -region="hq-firewall" -interval=60s
```

### 2. Docker: Read-Only DNS Log File (Bind9, Unbound, Windows AD DNS, Pi-hole)

```bash
docker run -d --name inferping-dns-collector --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  -v /var/log/named:/logs:ro \
  -e INFERPING_API_KEY="inf_live_your_workspace_key" \
  ghcr.io/inferping/inferping-dns-collector:latest \
  -dns-log=/logs/query.log -region="hq-amsterdam" -interval=60s
```

### 3. Tap Existing Grafana Loki, Splunk, HTTP HEC, or Kafka (Zero DNS / Firewall Changes)

```bash
# Grafana Loki
inferping-dns-collector -loki-url="https://loki.internal:3100" -loki-query='{job="coredns"}' -region="k8s-eu"

# Splunk Search Export
inferping-dns-collector -splunk-url="https://splunk.internal:8089" -splunk-query='index=dns OR index=proxy' -region="corp-siem"

# Local Splunk HEC / Loki Push / Vector / Cribl HTTP Sink
INFERPING_HTTP_INGEST_TOKEN="secret" inferping-dns-collector -http-listen="0.0.0.0:8088" -region="cribl-edge"

# Apache Kafka / Redpanda Topic Tailer
inferping-dns-collector -kafka-brokers="kafka-1.internal:9092,kafka-2.internal:9092" -kafka-topic="dns-queries" -kafka-tls -region="sec-bus"
```

### 4. Kubernetes & systemd

- **Kubernetes Deployment + Service**: [`deploy/k8s/dns-collector.yaml`](./deploy/k8s/dns-collector.yaml) (`kubectl apply -f deploy/k8s/dns-collector.yaml`)
- **Linux systemd**: [`deploy/systemd/inferping-dns-collector.service`](./deploy/systemd/inferping-dns-collector.service)

---

## 60-Second Engineer Verification

1. Verify at least `1` notification channel (Email, Slack, Microsoft Teams, Push, or Webhook) in **[app.inferping.eu](https://app.inferping.eu)**.
2. Run a direct DNS lookup against the monitored resolver (bypassing browser DNS-over-HTTPS and warm local OS DNS caches):
   ```bash
   nslookup chat.deepseek.com <your-monitored-dns-ip>
   ```
3. Within 60 seconds, `inferping-dns-collector` flushes the anonymized delta (`hits >= 1`), triggering one correlated policy alert with links to your **AI Governance Portal**, **TV Wallboard**, and **Employee AI Board** (repeat alerts per restricted tool are suppressed for 24h while live dashboard counters continue updating every minute).

---

## Related Repositories

- **[InferPing (`inferping.eu`)](https://inferping.eu)**: European AI Governance, Employee Approved-AI Directory, and AI Gateway Monitoring (`100% EU: NL, PL & DE`).
- **[`inferping-probe`](https://github.com/inferping/inferping-probe)**: Separate synthetic check binary for AI platform teams measuring internal VPC LLM streaming latency (`TTFT`) and gateway availability.

## License

Apache License 2.0 - Built in the Netherlands (EU) by **[InferPing](https://inferping.eu)** (Vallocor Security Engineering / GREYPIXEL ICT).
