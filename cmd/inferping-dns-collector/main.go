package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/inferping/inferping-dns-collector/catalogue"
)

var version = "1.0.0"

func main() {
	dnsLog := flag.String("dns-log", "", "Path to read-only DNS resolver, proxy, or firewall log file (strips client IPs in RAM)")
	fromStart := flag.Bool("from-start", false, "Read existing -dns-log from byte 0 on startup instead of tailing recent bytes")
	syslogListen := flag.String("syslog-listen", "", "Optional UDP+TCP syslog listen address (e.g. 0.0.0.0:5514)")
	syslogTLSListen := flag.String("syslog-tls-listen", "", "Optional RFC 5425 encrypted Syslog-over-TLS listen address (e.g. 0.0.0.0:6514)")
	syslogTLSCert := flag.String("syslog-tls-cert", "", "Server TLS certificate PEM path for -syslog-tls-listen")
	syslogTLSKey := flag.String("syslog-tls-key", "", "Server TLS private key PEM path for -syslog-tls-listen")
	syslogTLSClientCA := flag.String("syslog-tls-client-ca", "", "Optional client CA PEM bundle to enforce mutual TLS (mTLS) on -syslog-tls-listen")
	httpListen := flag.String("http-listen", "", "Optional local HTTP log receiver (e.g. 127.0.0.1:8088) for Splunk HEC, Grafana Loki Push, Vector, Cribl, or Fluent Bit")
	httpTokenEnv := flag.String("http-token-env", "INFERPING_HTTP_INGEST_TOKEN", "Optional env var holding a shared Bearer/Splunk HEC token required by -http-listen")
	lokiURL := flag.String("loki-url", "", "Optional Grafana Loki base URL (e.g. https://loki.internal:3100) to query DNS/proxy logs")
	lokiQuery := flag.String("loki-query", "", "LogQL selector for -loki-url (e.g. '{job=\"coredns\"}')")
	lokiOrgID := flag.String("loki-org-id", "", "Optional X-Scope-OrgID header for multi-tenant Grafana Loki")
	splunkURL := flag.String("splunk-url", "", "Optional Splunk management API URL (e.g. https://splunk.internal:8089) for streaming DNS/proxy export")
	splunkQuery := flag.String("splunk-query", "", "Splunk SPL query for -splunk-url (e.g. 'index=dns OR index=proxy')")
	sourceAuthEnv := flag.String("source-auth-env", "INFERPING_SOURCE_AUTH", "Environment variable holding Bearer/Basic/Splunk token for -loki-url or -splunk-url")
	kafkaBrokers := flag.String("kafka-brokers", "", "Optional comma-separated Kafka/Redpanda broker list (e.g. kafka-1.internal:9092,kafka-2.internal:9092)")
	kafkaTopic := flag.String("kafka-topic", "", "Kafka/Redpanda topic carrying DNS or proxy logs for -kafka-brokers")
	kafkaTLS := flag.Bool("kafka-tls", false, "Use TLS 1.2+ when connecting to -kafka-brokers")
	kafkaSASLEnv := flag.String("kafka-sasl-env", "INFERPING_KAFKA_SASL", "Optional env var holding 'username:password' for Kafka SASL/PLAIN")
	airgapped := flag.Bool("airgapped", false, "Airgapped/offline mode: disable central catalogue sync and use strictly the preloaded embedded domain list (+ optional -catalogue-file)")
	catalogueURL := flag.String("catalogue-url", "https://app.inferping.eu/v1/ai-catalogue.json", "Central AI domain catalogue URL synced every 5m via ETag (ignored when -airgapped is set)")
	catalogueFile := flag.String("catalogue-file", "", "Optional local JSON file with extra vendor AI domains to merge into the preloaded catalogue")
	region := flag.String("region", "", "Site or network zone label (e.g. hq-amsterdam, branch-munich, vpn-eu)")
	pushURL := flag.String("push-url", "https://app.inferping.eu/v1/metrics", "Outbound OpenTelemetry OTLP/HTTP metrics endpoint")
	apiKeyEnv := flag.String("api-key-env", "INFERPING_API_KEY", "Environment variable holding your inf_live_... workspace key")
	interval := flag.Duration("interval", 0, "Aggregation flush interval (defaults to 60s when streaming listeners or log connectors are active)")
	dryRun := flag.Bool("dry-run", false, "Print anonymized domain hit counts to stdout without sending OTLP metrics")
	showVersion := flag.Bool("version", false, "Print version and preloaded domain count, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("inferping-dns-collector v%s (https://github.com/inferping/inferping-dns-collector, preloaded catalogue %s with %d domains)\n", version, catalogue.Version(), catalogue.DomainCount())
		return
	}

	if strings.TrimSpace(*catalogueFile) != "" {
		if _, err := catalogue.LoadFile(*catalogueFile); err != nil {
			fmt.Fprintf(os.Stderr, "[inferping-dns-collector] failed to load -catalogue-file %s: %v\n", *catalogueFile, err)
			os.Exit(1)
		}
	}

	siteRegion := strings.TrimSpace(*region)
	if siteRegion == "" {
		siteRegion = strings.TrimSpace(os.Getenv("INFERPING_REGION"))
		if siteRegion == "" {
			siteRegion = "office-vlan"
		}
	}

	hasStream := strings.TrimSpace(*syslogListen) != "" ||
		strings.TrimSpace(*syslogTLSListen) != "" ||
		strings.TrimSpace(*httpListen) != "" ||
		strings.TrimSpace(*kafkaBrokers) != "" ||
		strings.TrimSpace(*lokiURL) != "" ||
		strings.TrimSpace(*splunkURL) != ""

	if strings.TrimSpace(*dnsLog) == "" && !hasStream {
		fmt.Fprintln(os.Stderr, "[inferping-dns-collector] specify at least one log source: -dns-log, -syslog-listen, -syslog-tls-listen, -http-listen, -loki-url, -splunk-url, or -kafka-brokers")
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var counter *catalogue.Counter
	if strings.TrimSpace(*syslogListen) != "" || strings.TrimSpace(*syslogTLSListen) != "" || strings.TrimSpace(*httpListen) != "" || strings.TrimSpace(*kafkaBrokers) != "" {
		counter = catalogue.NewCounter()
	}
	if strings.TrimSpace(*syslogListen) != "" {
		if err := counter.ListenAndServe(ctx, *syslogListen); err != nil {
			fmt.Fprintf(os.Stderr, "[inferping-dns-collector] failed to bind -syslog-listen %s: %v\n", *syslogListen, err)
			os.Exit(1)
		}
	}
	if strings.TrimSpace(*syslogTLSListen) != "" {
		if err := counter.ListenAndServeTLS(ctx, *syslogTLSListen, *syslogTLSCert, *syslogTLSKey, *syslogTLSClientCA); err != nil {
			fmt.Fprintf(os.Stderr, "[inferping-dns-collector] failed to bind -syslog-tls-listen %s: %v\n", *syslogTLSListen, err)
			os.Exit(1)
		}
	}
	if strings.TrimSpace(*httpListen) != "" {
		httpTok := strings.TrimSpace(os.Getenv(*httpTokenEnv))
		if _, err := catalogue.StartHTTPLogSink(ctx, *httpListen, httpTok, counter); err != nil {
			fmt.Fprintf(os.Stderr, "[inferping-dns-collector] failed to bind -http-listen %s: %v\n", *httpListen, err)
			os.Exit(1)
		}
	}
	if strings.TrimSpace(*kafkaBrokers) != "" {
		saslCreds := strings.TrimSpace(os.Getenv(*kafkaSASLEnv))
		if err := catalogue.StartKafkaTailer(ctx, *kafkaBrokers, *kafkaTopic, *kafkaTLS, saslCreds, counter); err != nil {
			fmt.Fprintf(os.Stderr, "[inferping-dns-collector] failed to start -kafka-brokers %s tailer: %v\n", *kafkaBrokers, err)
			os.Exit(1)
		}
	}
	if hasStream && *interval <= 0 {
		*interval = 60 * time.Second
	}

	var (
		lastLogOffset     int64
		lastLogHeadHash   string
		offsetInitialized bool
		lastCatalogueSync time.Time
		lastCatalogueETag string
		lokiCursor        = time.Now().UTC().Add(-60 * time.Second)
	)

	maybeSyncCatalogue := func(apiKey string) {
		if *airgapped || strings.TrimSpace(*catalogueURL) == "" {
			return
		}
		if !lastCatalogueSync.IsZero() && time.Since(lastCatalogueSync) < 5*time.Minute {
			return
		}
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if etag, _, err := catalogue.SyncFromURL(sctx, *catalogueURL, apiKey, lastCatalogueETag); err == nil {
			lastCatalogueETag = etag
		}
		lastCatalogueSync = time.Now()
	}

	maybeSyncCatalogue(strings.TrimSpace(os.Getenv(*apiKeyEnv)))

	step := func() bool {
		apiKey := strings.TrimSpace(os.Getenv(*apiKeyEnv))
		srcAuth := strings.TrimSpace(os.Getenv(*sourceAuthEnv))
		maybeSyncCatalogue(apiKey)

		mergedCounts := make(map[string]int)
		var sourceErrors []string

		var (
			nextOffset   = lastLogOffset
			nextHeadHash = lastLogHeadHash
			hasFileScan  bool
		)
		if strings.TrimSpace(*dnsLog) != "" {
			fc, candOffset, candHash, err := scanDNSLogDelta(*dnsLog, lastLogOffset, lastLogHeadHash, offsetInitialized, *fromStart || *interval <= 0)
			if err != nil {
				sourceErrors = append(sourceErrors, "dns-log: "+err.Error())
			} else {
				hasFileScan = true
				nextOffset = candOffset
				nextHeadHash = candHash
				for k, v := range fc {
					mergedCounts[k] += v
				}
			}
		}

		var drained map[string]int
		if counter != nil {
			drained = counter.Drain()
			for k, v := range drained {
				mergedCounts[k] += v
			}
		}

		if strings.TrimSpace(*lokiURL) != "" {
			nowUTC := time.Now().UTC()
			lc, nextCur, err := catalogue.FetchLokiCounts(ctx, *lokiURL, *lokiQuery, srcAuth, *lokiOrgID, lokiCursor, nowUTC)
			if err != nil {
				sourceErrors = append(sourceErrors, "loki: "+err.Error())
			} else {
				lokiCursor = nextCur
				for k, v := range lc {
					mergedCounts[k] += v
				}
			}
		}

		if strings.TrimSpace(*splunkURL) != "" {
			winStr := "-60s"
			if *interval > 0 {
				winStr = fmt.Sprintf("-%ds", int((*interval).Seconds()))
			}
			sc, err := catalogue.FetchSplunkCounts(ctx, *splunkURL, *splunkQuery, srcAuth, winStr, "now")
			if err != nil {
				sourceErrors = append(sourceErrors, "splunk: "+err.Error())
			} else {
				for k, v := range sc {
					mergedCounts[k] += v
				}
			}
		}

		var pushErr error
		cleanPush := strings.TrimSpace(*pushURL)
		if !*dryRun && cleanPush != "" && len(mergedCounts) > 0 && (!*airgapped || !strings.Contains(cleanPush, "inferping.eu")) {
			pushErr = pushDiscoveryOTLP(ctx, cleanPush, apiKey, siteRegion, mergedCounts)
			if pushErr != nil {
				if counter != nil && len(drained) > 0 {
					counter.Restore(drained)
				}
				sourceErrors = append(sourceErrors, "otlp-push: "+pushErr.Error())
			}
		}

		if pushErr == nil && hasFileScan {
			lastLogOffset = nextOffset
			lastLogHeadHash = nextHeadHash
			offsetInitialized = true
		}

		passed := len(sourceErrors) == 0
		summary := map[string]any{
			"collector":               "inferping-dns-collector",
			"version":                 version,
			"passed":                  passed,
			"airgapped":               *airgapped,
			"region":                  siteRegion,
			"catalogue_version":       catalogue.Version(),
			"catalogue_domains":       catalogue.DomainCount(),
			"anonymized_tools_active": len(mergedCounts),
			"tool_hits":               mergedCounts,
			"pii_stripped":            true,
		}
		if !passed {
			joined := strings.Join(sourceErrors, "; ")
			summary["error_msg"] = joined
			fmt.Fprintf(os.Stderr, "[inferping-dns-collector] %s\n", joined)
		}
		out, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(out))
		return passed
	}

	if *interval <= 0 {
		if !step() {
			os.Exit(1)
		}
		return
	}
	if counter == nil {
		step()
	}
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			step()
		}
	}
}

func scanDNSLogDelta(logPath string, prevOffset int64, prevHeadHash string, initialized bool, readFromStart bool) (map[string]int, int64, string, error) {
	f, err := os.Open(strings.TrimSpace(logPath))
	if err != nil {
		return nil, prevOffset, prevHeadHash, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, prevOffset, prevHeadHash, err
	}

	var headBuf [256]byte
	hn, _ := f.ReadAt(headBuf[:], 0)
	curHeadHash := ""
	if hn > 0 {
		sum := sha256.Sum256(headBuf[:hn])
		curHeadHash = hex.EncodeToString(sum[:8])
	}

	startOffset := prevOffset
	if !initialized && !readFromStart && st.Size() > 512*1024 {
		startOffset = st.Size() - 64*1024
	}
	if st.Size() < startOffset || (initialized && prevHeadHash != "" && curHeadHash != "" && curHeadHash != prevHeadHash) {
		startOffset = 0
	}
	if startOffset > 0 {
		_, _ = f.Seek(startOffset, 0)
	}
	counts, consumed := catalogue.ScanLogReaderWithBytes(f, 256*1024*1024)
	return counts, startOffset + consumed, curHeadHash, nil
}

func pushDiscoveryOTLP(ctx context.Context, pushURL, apiKey, region string, counts map[string]int) error {
	if strings.TrimSpace(apiKey) == "" && strings.Contains(pushURL, "inferping.eu") {
		return fmt.Errorf("missing INFERPING_API_KEY environment variable")
	}
	var dps []map[string]any
	for toolID, hits := range counts {
		if hits <= 0 {
			continue
		}
		dom := toolID
		if sig, ok := catalogue.LookupByID(toolID); ok {
			dom = sig.PrimaryDomain
		}
		dps = append(dps, map[string]any{
			"asDouble": float64(hits),
			"attributes": []map[string]any{
				{"key": "ai.tool.id", "value": map[string]string{"stringValue": toolID}},
				{"key": "ai.tool.domain", "value": map[string]string{"stringValue": dom}},
			},
		})
	}
	if len(dps) == 0 {
		return nil
	}
	payload := map[string]any{
		"resourceMetrics": []map[string]any{{
			"resource": map[string]any{
				"attributes": []map[string]any{
					{"key": "service.name", "value": map[string]string{"stringValue": "inferping-ai-discovery"}},
					{"key": "probe.region", "value": map[string]string{"stringValue": region}},
				},
			},
			"scopeMetrics": []map[string]any{{
				"metrics": []map[string]any{{
					"name":  "inferping.ai.discovery.hits",
					"gauge": map[string]any{"dataPoints": dps},
				}},
			}},
		}},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return nil
}
