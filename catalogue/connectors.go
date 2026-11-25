package catalogue

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func applySourceAuthHeader(req *http.Request, rawAuth string) {
	a := strings.TrimSpace(rawAuth)
	if a == "" {
		return
	}
	low := strings.ToLower(a)
	if strings.HasPrefix(low, "bearer ") || strings.HasPrefix(low, "basic ") || strings.HasPrefix(low, "splunk ") {
		req.Header.Set("Authorization", a)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a)
}

// FetchLokiCounts queries Grafana Loki's /loki/api/v1/query_range endpoint over [start, end],
// strips all client IPs/labels in memory, and returns anonymized AI tool counts plus the next high-water timestamp.
func FetchLokiCounts(ctx context.Context, lokiBaseURL, logQL, authToken, orgID string, start, end time.Time) (map[string]int, time.Time, error) {
	base := strings.TrimRight(strings.TrimSpace(lokiBaseURL), "/")
	q := strings.TrimSpace(logQL)
	if base == "" || q == "" {
		return nil, start, fmt.Errorf("missing loki url or LogQL query")
	}
	u, err := url.Parse(base + "/loki/api/v1/query_range")
	if err != nil {
		return nil, start, err
	}
	params := u.Query()
	params.Set("query", q)
	params.Set("start", strconv.FormatInt(start.UTC().UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UTC().UnixNano(), 10))
	params.Set("limit", "5000")
	params.Set("direction", "FORWARD")
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, start, err
	}
	req.Header.Set("Accept", "application/json")
	applySourceAuthHeader(req, authToken)
	if strings.TrimSpace(orgID) != "" {
		req.Header.Set("X-Scope-OrgID", strings.TrimSpace(orgID))
	}

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, start, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, start, fmt.Errorf("loki HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, start, err
	}
	var doc struct {
		Data struct {
			Result []struct {
				Values [][2]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, start, err
	}

	counts := make(map[string]int)
	maxNS := start.UTC().UnixNano()
	for _, stream := range doc.Data.Result {
		for _, pair := range stream.Values {
			if tsNS, pErr := strconv.ParseInt(pair[0], 10, 64); pErr == nil && tsNS >= maxNS {
				maxNS = tsNS + 1
			}
			for _, sig := range MatchAllLines(pair[1]) {
				counts[sig.ToolID]++
			}
		}
	}
	nextStart := end
	if maxNS > end.UTC().UnixNano() || len(counts) > 0 {
		nextStart = time.Unix(0, maxNS).UTC()
	}
	return counts, nextStart, nil
}

// FetchSplunkCounts runs a bounded streaming export against Splunk's REST API (/services/search/jobs/export),
// extracts matching AI tool domains in memory without storing _raw events or client IPs, and returns anonymized counts.
func FetchSplunkCounts(ctx context.Context, splunkBaseURL, splunkQuery, authToken, earliest, latest string) (map[string]int, error) {
	base := strings.TrimRight(strings.TrimSpace(splunkBaseURL), "/")
	q := strings.TrimSpace(splunkQuery)
	if base == "" || q == "" {
		return nil, fmt.Errorf("missing splunk url or search query")
	}
	if !strings.HasPrefix(strings.ToLower(q), "search ") && !strings.HasPrefix(q, "|") {
		q = "search " + q
	}
	if earliest == "" {
		earliest = "-60s"
	}
	if latest == "" {
		latest = "now"
	}

	form := url.Values{}
	form.Set("search", q)
	form.Set("earliest_time", earliest)
	form.Set("latest_time", latest)
	form.Set("output_mode", "json")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/services/search/jobs/export", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applySourceAuthHeader(req, authToken)

	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("splunk HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	counts := make(map[string]int)
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 32*1024*1024))
	sc.Buffer(make([]byte, 64*1024), 512*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			Result map[string]any `json:"result"`
		}
		if jErr := json.Unmarshal([]byte(line), &row); jErr == nil && len(row.Result) > 0 {
			if rawEv, ok := row.Result["_raw"].(string); ok && rawEv != "" {
				for _, sig := range MatchAllLines(rawEv) {
					counts[sig.ToolID]++
				}
				continue
			}
			flat, _ := json.Marshal(row.Result)
			for _, sig := range MatchAllLines(string(flat)) {
				counts[sig.ToolID]++
			}
			continue
		}
		for _, sig := range MatchAllLines(line) {
			counts[sig.ToolID]++
		}
	}
	return counts, nil
}

// StartHTTPLogSink starts a local HTTP log receiver compatible with Splunk HEC, Grafana Loki Push,
// Vector, Fluent Bit, Cribl Stream, Cloudflare Logpush, and Kafka Connect HTTP Sink.
func StartHTTPLogSink(ctx context.Context, listenAddr, requiredToken string, counter *Counter) (string, error) {
	addr := strings.TrimSpace(listenAddr)
	if addr == "" || counter == nil {
		return "", fmt.Errorf("missing http listen address or counter")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	cleanTok := strings.TrimSpace(requiredToken)

	checkAuth := func(r *http.Request) bool {
		if cleanTok == "" {
			return true
		}
		hdr := strings.TrimSpace(r.Header.Get("Authorization"))
		for _, pfx := range []string{"Bearer ", "bearer ", "Splunk ", "splunk "} {
			if strings.HasPrefix(hdr, pfx) {
				hdr = strings.TrimSpace(strings.TrimPrefix(hdr, pfx))
				break
			}
		}
		if hdr == "" {
			hdr = strings.TrimSpace(r.Header.Get("X-API-Key"))
		}
		return subtle.ConstantTimeCompare([]byte(hdr), []byte(cleanTok)) == 1
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/services/collector/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
	})

	ingestHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkAuth(r) {
			http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		var reader io.Reader = r.Body
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
			gz, gzErr := gzip.NewReader(r.Body)
			if gzErr != nil {
				http.Error(w, "Invalid gzip body", http.StatusBadRequest)
				return
			}
			defer gz.Close()
			reader = io.LimitReader(gz, 8<<20)
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			http.Error(w, "Payload too large or unreadable", http.StatusBadRequest)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/loki/api/v1/push") {
			var lokiPush struct {
				Streams []struct {
					Values [][2]string `json:"values"`
				} `json:"streams"`
			}
			if jErr := json.Unmarshal(raw, &lokiPush); jErr == nil && len(lokiPush.Streams) > 0 {
				for _, st := range lokiPush.Streams {
					for _, pair := range st.Values {
						counter.Ingest(pair[1])
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			counter.Ingest(sc.Text())
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}

	mux.HandleFunc("/ingest", ingestHandler)
	mux.HandleFunc("/loki/api/v1/push", ingestHandler)
	mux.HandleFunc("/services/collector", ingestHandler)
	mux.HandleFunc("/services/collector/event", ingestHandler)
	mux.HandleFunc("/services/collector/raw", ingestHandler)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sCtx)
	}()
	go func() {
		_ = srv.Serve(ln)
	}()
	return ln.Addr().String(), nil
}

// StartKafkaTailer runs a zero-dependency Kafka/Redpanda binary wire-protocol tailer across all partitions
// of the given topic (supporting TCP, TLS 1.2+, and optional SASL/PLAIN "user:password").
// It tails latest partition offsets directly without registering a consumer group, ensuring zero impact on broker state.
func StartKafkaTailer(ctx context.Context, brokersCSV, topic string, useTLS bool, saslPlain string, counter *Counter) error {
	cleanTopic := strings.TrimSpace(topic)
	if cleanTopic == "" || counter == nil {
		return fmt.Errorf("missing kafka topic or counter")
	}
	var seedBrokers []string
	for _, b := range strings.Split(brokersCSV, ",") {
		if cb := strings.TrimSpace(b); cb != "" {
			seedBrokers = append(seedBrokers, cb)
		}
	}
	if len(seedBrokers) == 0 {
		return fmt.Errorf("missing kafka brokers")
	}

	dialBroker := func(addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 8 * time.Second}
		var conn net.Conn
		var err error
		if useTLS {
			host, _, sErr := net.SplitHostPort(addr)
			if sErr != nil {
				host = addr
			}
			conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		} else {
			conn, err = d.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(saslPlain) != "" {
			if sErr := kafkaSASLPlainAuth(conn, saslPlain); sErr != nil {
				_ = conn.Close()
				return nil, sErr
			}
		}
		return conn, nil
	}

	partLeaders, err := kafkaDiscoverPartitions(seedBrokers, cleanTopic, dialBroker)
	if err != nil {
		return err
	}
	for partID, brokerAddr := range partLeaders {
		go kafkaTailPartitionLoop(ctx, brokerAddr, seedBrokers, cleanTopic, partID, dialBroker, counter)
	}
	return nil
}

func kafkaWriteRequest(conn net.Conn, apiKey int16, apiVersion int16, corrID int32, body []byte) ([]byte, error) {
	clientID := "inferping-dns-collector"
	hdrLen := 2 + 2 + 4 + 2 + len(clientID)
	totalLen := hdrLen + len(body)
	var pkt bytes.Buffer
	pkt.Grow(4 + totalLen)
	_ = binary.Write(&pkt, binary.BigEndian, int32(totalLen))
	_ = binary.Write(&pkt, binary.BigEndian, apiKey)
	_ = binary.Write(&pkt, binary.BigEndian, apiVersion)
	_ = binary.Write(&pkt, binary.BigEndian, corrID)
	_ = binary.Write(&pkt, binary.BigEndian, int16(len(clientID)))
	pkt.WriteString(clientID)
	pkt.Write(body)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil, err
	}
	var respSize int32
	if err := binary.Read(conn, binary.BigEndian, &respSize); err != nil {
		return nil, err
	}
	if respSize < 4 || respSize > 16*1024*1024 {
		return nil, fmt.Errorf("invalid kafka response frame size %d", respSize)
	}
	resp := make([]byte, respSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp[4:], nil
}

func kafkaSASLPlainAuth(conn net.Conn, userPass string) error {
	user, pass, ok := strings.Cut(strings.TrimSpace(userPass), ":")
	if !ok {
		return fmt.Errorf("kafka SASL credentials must be in username:password format")
	}
	var hs bytes.Buffer
	_ = binary.Write(&hs, binary.BigEndian, int16(5))
	hs.WriteString("PLAIN")
	hsResp, err := kafkaWriteRequest(conn, 17, 1, 1, hs.Bytes())
	if err != nil {
		return err
	}
	if len(hsResp) < 2 || int16(binary.BigEndian.Uint16(hsResp[:2])) != 0 {
		return fmt.Errorf("kafka SASL handshake rejected")
	}
	authRaw := append([]byte{0}, []byte(user)...)
	authRaw = append(authRaw, 0)
	authRaw = append(authRaw, []byte(pass)...)
	var ab bytes.Buffer
	_ = binary.Write(&ab, binary.BigEndian, int32(len(authRaw)))
	ab.Write(authRaw)
	aResp, err := kafkaWriteRequest(conn, 36, 0, 2, ab.Bytes())
	if err != nil {
		return err
	}
	if len(aResp) < 2 || int16(binary.BigEndian.Uint16(aResp[:2])) != 0 {
		return fmt.Errorf("kafka SASL authentication failed")
	}
	return nil
}

func kafkaDiscoverPartitions(seedBrokers []string, topic string, dial func(string) (net.Conn, error)) (map[int32]string, error) {
	var lastErr error
	for _, seed := range seedBrokers {
		conn, err := dial(seed)
		if err != nil {
			lastErr = err
			continue
		}
		var req bytes.Buffer
		_ = binary.Write(&req, binary.BigEndian, int32(1))
		_ = binary.Write(&req, binary.BigEndian, int16(len(topic)))
		req.WriteString(topic)
		resp, rErr := kafkaWriteRequest(conn, 3, 0, 10, req.Bytes())
		_ = conn.Close()
		if rErr != nil {
			lastErr = rErr
			continue
		}
		leaders, pErr := parseKafkaMetadataV0(resp, topic)
		if pErr != nil {
			lastErr = pErr
			continue
		}
		return leaders, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable kafka brokers")
	}
	return nil, lastErr
}

func parseKafkaMetadataV0(b []byte, wantTopic string) (map[int32]string, error) {
	r := bytes.NewReader(b)
	var brokerCnt int32
	if err := binary.Read(r, binary.BigEndian, &brokerCnt); err != nil || brokerCnt < 0 || brokerCnt > 1024 {
		return nil, fmt.Errorf("invalid kafka broker metadata")
	}
	brokers := make(map[int32]string, brokerCnt)
	for i := int32(0); i < brokerCnt; i++ {
		var nodeID, port int32
		var hostLen int16
		if binary.Read(r, binary.BigEndian, &nodeID) != nil || binary.Read(r, binary.BigEndian, &hostLen) != nil || hostLen < 0 || hostLen > 512 {
			return nil, fmt.Errorf("truncated kafka broker entry")
		}
		hostBytes := make([]byte, hostLen)
		if _, err := io.ReadFull(r, hostBytes); err != nil || binary.Read(r, binary.BigEndian, &port) != nil {
			return nil, fmt.Errorf("truncated kafka broker host")
		}
		brokers[nodeID] = net.JoinHostPort(string(hostBytes), strconv.Itoa(int(port)))
	}
	var topicCnt int32
	if binary.Read(r, binary.BigEndian, &topicCnt) != nil || topicCnt <= 0 || topicCnt > 256 {
		return nil, fmt.Errorf("kafka topic %q not found", wantTopic)
	}
	leaders := make(map[int32]string)
	for t := int32(0); t < topicCnt; t++ {
		var tErr, nameLen int16
		if binary.Read(r, binary.BigEndian, &tErr) != nil || binary.Read(r, binary.BigEndian, &nameLen) != nil || nameLen < 0 || nameLen > 512 {
			return nil, fmt.Errorf("invalid kafka topic header")
		}
		tName := make([]byte, nameLen)
		var partCnt int32
		if _, err := io.ReadFull(r, tName); err != nil || binary.Read(r, binary.BigEndian, &partCnt) != nil || partCnt < 0 || partCnt > 4096 {
			return nil, fmt.Errorf("invalid kafka partition count")
		}
		if tErr != 0 {
			return nil, fmt.Errorf("kafka topic %q error code %d", string(tName), tErr)
		}
		for p := int32(0); p < partCnt; p++ {
			var pErr int16
			var partID, leaderID, repCnt, isrCnt int32
			if binary.Read(r, binary.BigEndian, &pErr) != nil ||
				binary.Read(r, binary.BigEndian, &partID) != nil ||
				binary.Read(r, binary.BigEndian, &leaderID) != nil ||
				binary.Read(r, binary.BigEndian, &repCnt) != nil {
				return nil, fmt.Errorf("truncated kafka partition metadata")
			}
			if repCnt > 0 {
				_, _ = io.CopyN(io.Discard, r, int64(repCnt)*4)
			}
			if binary.Read(r, binary.BigEndian, &isrCnt) != nil {
				return nil, fmt.Errorf("truncated kafka isr metadata")
			}
			if isrCnt > 0 {
				_, _ = io.CopyN(io.Discard, r, int64(isrCnt)*4)
			}
			if string(tName) == wantTopic {
				if addr, ok := brokers[leaderID]; ok {
					leaders[partID] = addr
				}
			}
		}
	}
	if len(leaders) == 0 {
		return nil, fmt.Errorf("no active partition leaders for kafka topic %q", wantTopic)
	}
	return leaders, nil
}

func kafkaQueryLatestOffset(conn net.Conn, topic string, partition int32) (int64, error) {
	var req bytes.Buffer
	_ = binary.Write(&req, binary.BigEndian, int32(-1))
	_ = binary.Write(&req, binary.BigEndian, int32(1))
	_ = binary.Write(&req, binary.BigEndian, int16(len(topic)))
	req.WriteString(topic)
	_ = binary.Write(&req, binary.BigEndian, int32(1))
	_ = binary.Write(&req, binary.BigEndian, partition)
	_ = binary.Write(&req, binary.BigEndian, int64(-1))

	resp, err := kafkaWriteRequest(conn, 2, 1, 20, req.Bytes())
	if err != nil {
		return 0, err
	}
	r := bytes.NewReader(resp)
	var topicCnt int32
	var nameLen int16
	if binary.Read(r, binary.BigEndian, &topicCnt) != nil || topicCnt < 1 || binary.Read(r, binary.BigEndian, &nameLen) != nil || nameLen < 0 {
		return 0, fmt.Errorf("invalid kafka ListOffsets response")
	}
	_, _ = io.CopyN(io.Discard, r, int64(nameLen))
	var partCnt, pID int32
	var errCode int16
	var ts, offset int64
	if binary.Read(r, binary.BigEndian, &partCnt) != nil || partCnt < 1 ||
		binary.Read(r, binary.BigEndian, &pID) != nil ||
		binary.Read(r, binary.BigEndian, &errCode) != nil ||
		binary.Read(r, binary.BigEndian, &ts) != nil ||
		binary.Read(r, binary.BigEndian, &offset) != nil {
		return 0, fmt.Errorf("truncated kafka ListOffsets partition")
	}
	if errCode != 0 {
		return 0, fmt.Errorf("kafka ListOffsets error %d", errCode)
	}
	return offset, nil
}

func kafkaTailPartitionLoop(ctx context.Context, leaderAddr string, seeds []string, topic string, partition int32, dial func(string) (net.Conn, error), counter *Counter) {
	var (
		conn       net.Conn
		nextOffset int64 = -1
		corrID     int32 = 100
	)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if conn == nil {
			c, err := dial(leaderAddr)
			if err != nil {
				if mp, mErr := kafkaDiscoverPartitions(seeds, topic, dial); mErr == nil && mp[partition] != "" {
					leaderAddr = mp[partition]
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
			conn = c
			if nextOffset < 0 {
				off, oErr := kafkaQueryLatestOffset(conn, topic, partition)
				if oErr != nil {
					_ = conn.Close()
					conn = nil
					time.Sleep(time.Second)
					continue
				}
				nextOffset = off
			}
		}

		var req bytes.Buffer
		_ = binary.Write(&req, binary.BigEndian, int32(-1))
		_ = binary.Write(&req, binary.BigEndian, int32(1500))
		_ = binary.Write(&req, binary.BigEndian, int32(1))
		_ = binary.Write(&req, binary.BigEndian, int32(1))
		_ = binary.Write(&req, binary.BigEndian, int16(len(topic)))
		req.WriteString(topic)
		_ = binary.Write(&req, binary.BigEndian, int32(1))
		_ = binary.Write(&req, binary.BigEndian, partition)
		_ = binary.Write(&req, binary.BigEndian, nextOffset)
		_ = binary.Write(&req, binary.BigEndian, int32(1<<20))

		corrID++
		resp, err := kafkaWriteRequest(conn, 1, 2, corrID, req.Bytes())
		if err != nil {
			_ = conn.Close()
			conn = nil
			continue
		}
		advanced, fErr := consumeKafkaFetchV2(resp, nextOffset, counter)
		if fErr != nil {
			_ = conn.Close()
			conn = nil
			continue
		}
		if advanced > nextOffset {
			nextOffset = advanced
		}
	}
}

func consumeKafkaFetchV2(b []byte, prevOffset int64, counter *Counter) (int64, error) {
	r := bytes.NewReader(b)
	var throttleMS, topicCnt int32
	var nameLen int16
	if binary.Read(r, binary.BigEndian, &throttleMS) != nil ||
		binary.Read(r, binary.BigEndian, &topicCnt) != nil || topicCnt < 1 ||
		binary.Read(r, binary.BigEndian, &nameLen) != nil || nameLen < 0 {
		return prevOffset, fmt.Errorf("invalid kafka Fetch v2 header")
	}
	_, _ = io.CopyN(io.Discard, r, int64(nameLen))
	var partCnt, pID, msgSetSize int32
	var errCode int16
	var highWatermark int64
	if binary.Read(r, binary.BigEndian, &partCnt) != nil || partCnt < 1 ||
		binary.Read(r, binary.BigEndian, &pID) != nil ||
		binary.Read(r, binary.BigEndian, &errCode) != nil ||
		binary.Read(r, binary.BigEndian, &highWatermark) != nil ||
		binary.Read(r, binary.BigEndian, &msgSetSize) != nil {
		return prevOffset, fmt.Errorf("truncated kafka Fetch v2 partition")
	}
	if errCode != 0 {
		return prevOffset, fmt.Errorf("kafka Fetch partition error %d", errCode)
	}
	if msgSetSize <= 0 {
		return prevOffset, nil
	}
	if msgSetSize > 16*1024*1024 {
		return prevOffset, fmt.Errorf("oversized kafka message set")
	}
	msgBytes := make([]byte, msgSetSize)
	if _, err := io.ReadFull(r, msgBytes); err != nil {
		return prevOffset, err
	}
	return decodeKafkaRecords(msgBytes, prevOffset, highWatermark, counter), nil
}

func decodeKafkaRecords(buf []byte, prevOffset, highWatermark int64, counter *Counter) int64 {
	nextOff := prevOffset
	pos := 0
	for pos+12 <= len(buf) {
		baseOffset := int64(binary.BigEndian.Uint64(buf[pos : pos+8]))
		batchLen := int(int32(binary.BigEndian.Uint32(buf[pos+8 : pos+12])))
		if batchLen <= 4 || pos+12+batchLen > len(buf) {
			break
		}
		frame := buf[pos+12 : pos+12+batchLen]
		pos += 12 + batchLen

		magic := frame[4]
		if magic == 2 && len(frame) >= 49 {
			lastOffDelta := int64(int32(binary.BigEndian.Uint32(frame[11:15])))
			attrs := binary.BigEndian.Uint16(frame[9:11])
			recCnt := int(int32(binary.BigEndian.Uint32(frame[45:49])))
			if (attrs&0x07) == 0 && recCnt > 0 {
				rp := 49
				for k := 0; k < recCnt && rp < len(frame); k++ {
					recLen, n1 := binary.Varint(frame[rp:])
					if n1 <= 0 || recLen <= 0 || rp+n1+int(recLen) > len(frame) {
						break
					}
					recBody := frame[rp+n1 : rp+n1+int(recLen)]
					rp += n1 + int(recLen)
					if val := extractKafkaV2RecordValue(recBody); len(val) > 0 {
						counter.Ingest(string(val))
					}
				}
			} else {
				counter.Ingest(string(frame[49:]))
			}
			if baseOffset+lastOffDelta+1 > nextOff {
				nextOff = baseOffset + lastOffDelta + 1
			}
			continue
		}

		valPos := 6
		if magic == 1 {
			valPos += 8
		}
		if valPos+4 <= len(frame) {
			keyLen := int(int32(binary.BigEndian.Uint32(frame[valPos : valPos+4])))
			valPos += 4
			if keyLen > 0 {
				valPos += keyLen
			}
			if valPos+4 <= len(frame) {
				vLen := int(int32(binary.BigEndian.Uint32(frame[valPos : valPos+4])))
				valPos += 4
				if vLen > 0 && valPos+vLen <= len(frame) {
					counter.Ingest(string(frame[valPos : valPos+vLen]))
				}
			}
		}
		if baseOffset+1 > nextOff {
			nextOff = baseOffset + 1
		}
	}
	if nextOff <= prevOffset && highWatermark > prevOffset {
		nextOff = highWatermark
	}
	return nextOff
}

func extractKafkaV2RecordValue(rec []byte) []byte {
	if len(rec) < 4 {
		return nil
	}
	idx := 1
	for skip := 0; skip < 2; skip++ {
		_, n := binary.Varint(rec[idx:])
		if n <= 0 {
			return nil
		}
		idx += n
	}
	keyLen, nk := binary.Varint(rec[idx:])
	if nk <= 0 {
		return nil
	}
	idx += nk
	if keyLen > 0 {
		if idx+int(keyLen) > len(rec) {
			return nil
		}
		idx += int(keyLen)
	}
	valLen, nv := binary.Varint(rec[idx:])
	if nv <= 0 || valLen <= 0 {
		return nil
	}
	idx += nv
	if idx+int(valLen) > len(rec) {
		return nil
	}
	return rec[idx : idx+int(valLen)]
}
