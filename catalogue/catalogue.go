package catalogue

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ai-tools.json
var embeddedCatalogueJSON []byte

// AIToolSignature describes a known external AI application or inference API domain
// for strictly passive, zero-PII domain counting.
type AIToolSignature struct {
	ToolID               string   `json:"tool_id"`
	DisplayName          string   `json:"display_name"`
	Vendor               string   `json:"vendor"`
	Category             string   `json:"category"`
	Region               string   `json:"region"`
	PrimaryDomain        string   `json:"primary_domain"`
	Domains              []string `json:"domains"`
	DefaultPolicy        string   `json:"default_policy"`
	RiskNote             string   `json:"risk_note"`
	SuggestedAlternative string   `json:"suggested_alternative"`
}

// CatalogueDocument represents the versioned domain list embedded in the collector binary
// and optionally synced via ETag from https://app.inferping.eu/v1/ai-catalogue.json.
type CatalogueDocument struct {
	Version     string            `json:"version"`
	UpdatedAt   string            `json:"updated_at"`
	Source      string            `json:"source,omitempty"`
	GitMirror   string            `json:"git_mirror,omitempty"`
	ToolCount   int               `json:"tool_count"`
	DomainCount int               `json:"domain_count"`
	Tools       []AIToolSignature `json:"tools"`
}

var (
	mu               sync.RWMutex
	active           []AIToolSignature
	domainMap        map[string]AIToolSignature
	idMap            map[string]AIToolSignature
	preloadedVersion = "embedded"
	forbiddenSuffix  = []string{".local", ".lan", ".internal", ".corp", ".home", ".arpa", ".intranet", ".localdomain"}
)

func init() {
	var doc CatalogueDocument
	if err := json.Unmarshal(embeddedCatalogueJSON, &doc); err == nil && len(doc.Tools) > 0 {
		if strings.TrimSpace(doc.Version) != "" {
			preloadedVersion = strings.TrimSpace(doc.Version)
		}
		rebuildLocked(sanitizeList(doc.Tools))
	}
}

func rebuildLocked(list []AIToolSignature) {
	cp := make([]AIToolSignature, len(list))
	copy(cp, list)
	dm := make(map[string]AIToolSignature, len(cp)*3)
	im := make(map[string]AIToolSignature, len(cp))
	for _, s := range cp {
		im[s.ToolID] = s
		for _, d := range s.Domains {
			if _, ok := dm[d]; !ok {
				dm[d] = s
			}
		}
	}
	active = cp
	domainMap = dm
	idMap = im
}

// IsSafePublicAIDomain verifies that a domain is a valid public FQDN and never an IP literal or internal corporate suffix.
func IsSafePublicAIDomain(raw string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(d) < 4 || len(d) > 96 || !strings.Contains(d, ".") || d == "localhost" || net.ParseIP(d) != nil {
		return false
	}
	for _, suf := range forbiddenSuffix {
		if strings.HasSuffix(d, suf) {
			return false
		}
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 || len(labels[len(labels)-1]) < 2 {
		return false
	}
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 || lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func sanitizeList(in []AIToolSignature) []AIToolSignature {
	out := make([]AIToolSignature, 0, len(in))
	seen := make(map[string]int, len(in))
	for _, s := range in {
		if len(out) >= 500 {
			break
		}
		s.ToolID = strings.ToLower(strings.TrimSpace(s.ToolID))
		s.PrimaryDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.PrimaryDomain), "."))
		if s.PrimaryDomain == "" && len(s.Domains) > 0 {
			s.PrimaryDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.Domains[0]), "."))
		}
		if !IsSafePublicAIDomain(s.PrimaryDomain) {
			continue
		}
		if s.ToolID == "" || len(s.ToolID) > 96 {
			s.ToolID = s.PrimaryDomain
		}
		var doms []string
		dseen := map[string]struct{}{}
		for _, cand := range append([]string{s.PrimaryDomain}, s.Domains...) {
			c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cand), "."))
			if IsSafePublicAIDomain(c) && len(doms) < 16 {
				if _, ok := dseen[c]; !ok {
					dseen[c] = struct{}{}
					doms = append(doms, c)
				}
			}
		}
		s.Domains = doms
		if idx, ok := seen[s.ToolID]; ok {
			out[idx] = s
		} else {
			seen[s.ToolID] = len(out)
			out = append(out, s)
		}
	}
	return out
}

func Version() string { return preloadedVersion }

func DomainCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(domainMap)
}

func Merge(ext []AIToolSignature) int {
	valid := sanitizeList(ext)
	if len(valid) == 0 {
		return 0
	}
	mu.Lock()
	defer mu.Unlock()
	byID := make(map[string]int, len(active)+len(valid))
	merged := make([]AIToolSignature, len(active))
	copy(merged, active)
	for i, s := range merged {
		byID[s.ToolID] = i
	}
	for _, v := range valid {
		if len(merged) >= 600 {
			break
		}
		if idx, ok := byID[v.ToolID]; ok {
			merged[idx] = v
		} else {
			byID[v.ToolID] = len(merged)
			merged = append(merged, v)
		}
	}
	rebuildLocked(merged)
	return len(valid)
}

func LoadFile(path string) (int, error) {
	f, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 2*1024*1024))
	if err != nil {
		return 0, err
	}
	return parseAndMerge(raw)
}

func parseAndMerge(raw []byte) (int, error) {
	t := strings.TrimSpace(string(raw))
	if strings.HasPrefix(t, "[") {
		var list []AIToolSignature
		if err := json.Unmarshal([]byte(t), &list); err != nil {
			return 0, err
		}
		return Merge(list), nil
	}
	var doc CatalogueDocument
	if err := json.Unmarshal([]byte(t), &doc); err != nil {
		return 0, err
	}
	return Merge(doc.Tools), nil
}

func SyncFromURL(ctx context.Context, url, apiKey, prevETag string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(url), nil)
	if err != nil {
		return prevETag, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "InferPing-DNS-Collector/1.0 (+https://github.com/inferping/inferping-dns-collector)")
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return prevETag, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return prevETag, 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return prevETag, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return prevETag, 0, err
	}
	n, err := parseAndMerge(raw)
	if err != nil {
		return prevETag, 0, err
	}
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	if etag == "" {
		etag = prevETag
	}
	return etag, n, nil
}

func LookupByID(toolID string) (AIToolSignature, bool) {
	q := strings.ToLower(strings.TrimSpace(toolID))
	mu.RLock()
	defer mu.RUnlock()
	if s, ok := idMap[q]; ok {
		return s, true
	}
	return matchSuffixLocked(q)
}

func matchSuffixLocked(cand string) (AIToolSignature, bool) {
	for len(cand) >= 4 {
		if s, ok := domainMap[cand]; ok {
			return s, true
		}
		dot := strings.IndexByte(cand, '.')
		if dot < 0 {
			break
		}
		cand = cand[dot+1:]
	}
	return AIToolSignature{}, false
}

func isTokChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '.'
}

// normalizeWindowsDNSWireLabels rewrites Microsoft Windows Server DNS debug log wire-format domains
// such as "(4)chat(8)deepseek(3)com(0)" into standard dotted FQDNs ("chat.deepseek.com").
func normalizeWindowsDNSWireLabels(rawLine string) string {
	firstParen := strings.IndexByte(rawLine, '(')
	if firstParen < 0 || strings.IndexByte(rawLine[firstParen:], ')') < 0 {
		return rawLine
	}
	n := len(rawLine)
	var b strings.Builder
	b.Grow(n)
	i := 0
	replacedAny := false
	for i < n {
		if rawLine[i] != '(' {
			b.WriteByte(rawLine[i])
			i++
			continue
		}
		cur := i
		labels := 0
		var segBuf [128]byte
		segLen := 0
		for cur < n && rawLine[cur] == '(' {
			closeIdx := cur + 1
			for closeIdx < n && closeIdx-cur <= 4 && rawLine[closeIdx] >= '0' && rawLine[closeIdx] <= '9' {
				closeIdx++
			}
			if closeIdx == cur+1 || closeIdx >= n || rawLine[closeIdx] != ')' {
				break
			}
			lblLen, err := strconv.Atoi(rawLine[cur+1 : closeIdx])
			if err != nil || lblLen < 0 || lblLen > 63 {
				break
			}
			if lblLen == 0 {
				cur = closeIdx + 1
				break
			}
			lblStart := closeIdx + 1
			lblEnd := lblStart + lblLen
			if lblEnd > n {
				lblEnd = lblStart
				for lblEnd < n && isTokChar(rawLine[lblEnd]) && rawLine[lblEnd] != '.' {
					lblEnd++
				}
				if lblEnd == lblStart {
					break
				}
			} else {
				valid := true
				for k := lblStart; k < lblEnd; k++ {
					c := rawLine[k]
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
						valid = false
						break
					}
				}
				if !valid {
					break
				}
			}
			actualLen := lblEnd - lblStart
			if segLen+actualLen+1 >= len(segBuf) {
				break
			}
			if labels > 0 {
				segBuf[segLen] = '.'
				segLen++
			}
			copy(segBuf[segLen:], rawLine[lblStart:lblEnd])
			segLen += actualLen
			labels++
			cur = lblEnd
		}
		if labels >= 2 && cur > i {
			b.WriteByte(' ')
			b.Write(segBuf[:segLen])
			b.WriteByte(' ')
			i = cur
			replacedAny = true
			continue
		}
		b.WriteByte(rawLine[i])
		i++
	}
	if !replacedAny {
		return rawLine
	}
	return b.String()
}

// MatchLine returns the first matched AI tool signature on a log line.
func MatchLine(rawLine string) (AIToolSignature, bool) {
	all := MatchAllLines(rawLine)
	if len(all) == 0 {
		return AIToolSignature{}, false
	}
	return all[0], true
}

// MatchAllLines extracts all distinct known AI tool domains from a single log line at 500+ MB/sec
// without retaining any client IP address, MAC address, or username.
func MatchAllLines(rawLine string) []AIToolSignature {
	if len(rawLine) < 4 {
		return nil
	}
	line := normalizeWindowsDNSWireLabels(rawLine)
	n := len(line)
	if n < 4 {
		return nil
	}
	mu.RLock()
	defer mu.RUnlock()

	var (
		lowerBuf [128]byte
		results  []AIToolSignature
	)
	i := 0
	for i < n {
		for i < n && !isTokChar(line[i]) {
			i++
		}
		start := i
		hasDot := false
		for i < n && isTokChar(line[i]) {
			if line[i] == '.' {
				hasDot = true
			}
			i++
		}
		end := i
		for end > start && (line[end-1] == '.' || line[end-1] == '-') {
			end--
		}
		for start < end && (line[start] == '.' || line[start] == '-') {
			start++
		}
		tlen := end - start
		if !hasDot || tlen < 4 || tlen > 120 {
			continue
		}
		last := line[end-1]
		if last >= '0' && last <= '9' {
			continue
		}
		for k := 0; k < tlen; k++ {
			c := line[start+k]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			lowerBuf[k] = c
		}
		if s, ok := matchSuffixLocked(string(lowerBuf[:tlen])); ok {
			dup := false
			for _, ex := range results {
				if ex.ToolID == s.ToolID {
					dup = true
					break
				}
			}
			if !dup {
				results = append(results, s)
			}
		}
	}
	return results
}

func ScanLogReader(r io.Reader) map[string]int {
	c, _ := ScanLogReaderWithBytes(r, 256*1024*1024)
	return c
}

func ScanLogReaderWithBytes(r io.Reader, maxBytes int64) (map[string]int, int64) {
	counts := make(map[string]int)
	if r == nil || maxBytes <= 0 {
		return counts, 0
	}
	cr := &cntReader{r: io.LimitReader(r, maxBytes)}
	sc := bufio.NewScanner(cr)
	buf := make([]byte, 64*1024)
	sc.Buffer(buf, 512*1024)
	for sc.Scan() {
		for _, sig := range MatchAllLines(sc.Text()) {
			counts[sig.ToolID]++
		}
	}
	return counts, cr.n
}

type cntReader struct {
	r io.Reader
	n int64
}

func (c *cntReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Counter aggregates matched AI domain hits in memory with zero client IP or log-line retention.
type Counter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewCounter() *Counter {
	return &Counter{counts: make(map[string]int)}
}

func (s *Counter) Ingest(payload string) {
	if len(payload) < 4 {
		return
	}
	for len(payload) > 0 {
		var line string
		if nl := strings.IndexByte(payload, '\n'); nl >= 0 {
			line = payload[:nl]
			payload = payload[nl+1:]
		} else {
			line = payload
			payload = ""
		}
		line = strings.TrimRight(line, "\r")
		if len(line) < 4 {
			continue
		}
		matches := MatchAllLines(line)
		if len(matches) > 0 {
			s.mu.Lock()
			for _, sig := range matches {
				if s.counts[sig.ToolID] < 10_000_000 {
					s.counts[sig.ToolID]++
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Counter) Restore(prev map[string]int) {
	if len(prev) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range prev {
		if v <= 0 {
			continue
		}
		if s.counts[k]+v > 10_000_000 {
			s.counts[k] = 10_000_000
		} else {
			s.counts[k] += v
		}
	}
}

func (s *Counter) Drain() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.counts) == 0 {
		return nil
	}
	out := s.counts
	s.counts = make(map[string]int)
	return out
}

// IngestSyslogStream parses both RFC 6587 octet-counted syslog frames ("<len> <<PRI>1 ...>")
// and newline-terminated syslog streams.
func (s *Counter) IngestSyslogStream(r io.Reader) {
	br := bufio.NewReaderSize(io.LimitReader(r, 256*1024*1024), 64*1024)
	for {
		b, err := br.Peek(1)
		if err != nil || len(b) == 0 {
			return
		}
		if b[0] >= '1' && b[0] <= '9' {
			var lenDigits [8]byte
			nDig := 0
			validOctet := false
			for nDig < len(lenDigits) {
				ch, rErr := br.ReadByte()
				if rErr != nil {
					return
				}
				if ch == ' ' {
					validOctet = nDig > 0
					break
				}
				if ch >= '0' && ch <= '9' {
					lenDigits[nDig] = ch
					nDig++
					continue
				}
				rest, _ := br.ReadString('\n')
				s.Ingest(string(lenDigits[:nDig]) + string(ch) + rest)
				validOctet = false
				nDig = -1
				break
			}
			if nDig == -1 {
				continue
			}
			if !validOctet {
				rest, _ := br.ReadString('\n')
				s.Ingest(rest)
				continue
			}
			frameLen, convErr := strconv.Atoi(string(lenDigits[:nDig]))
			if convErr != nil || frameLen <= 0 || frameLen > 65536 {
				return
			}
			frame := make([]byte, frameLen)
			if _, fErr := io.ReadFull(br, frame); fErr != nil {
				if len(frame) > 0 {
					s.Ingest(string(frame))
				}
				return
			}
			s.Ingest(string(frame))
			continue
		}
		line, lErr := br.ReadString('\n')
		if len(line) > 0 {
			s.Ingest(line)
		}
		if lErr != nil {
			return
		}
	}
}

func (s *Counter) serveConn(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Minute))
	s.IngestSyslogStream(c)
}

func (s *Counter) ListenAndServe(ctx context.Context, addr string) error {
	cleanAddr := strings.TrimSpace(addr)
	if cleanAddr == "" {
		return fmt.Errorf("empty syslog listen address")
	}
	udpConn, err := net.ListenPacket("udp", cleanAddr)
	if err != nil {
		return err
	}
	tcpLn, tcpErr := net.Listen("tcp", cleanAddr)
	go func() {
		<-ctx.Done()
		_ = udpConn.Close()
		if tcpLn != nil {
			_ = tcpLn.Close()
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, rErr := udpConn.ReadFrom(buf)
			if n > 0 {
				s.Ingest(string(buf[:n]))
			}
			if rErr != nil {
				return
			}
		}
	}()
	if tcpErr == nil && tcpLn != nil {
		go func() {
			for {
				conn, aErr := tcpLn.Accept()
				if aErr != nil {
					return
				}
				go s.serveConn(conn)
			}
		}()
	}
	return nil
}

// ListenAndServeTLS starts an RFC 5425 encrypted Syslog-over-TLS listener (TLS 1.2/1.3, optional mTLS client CA verification,
// and both RFC 6587 octet-counted and newline-delimited framing).
func (s *Counter) ListenAndServeTLS(ctx context.Context, addr, certFile, keyFile, clientCAFile string) error {
	cleanAddr := strings.TrimSpace(addr)
	if cleanAddr == "" {
		return fmt.Errorf("empty syslog TLS listen address")
	}
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(certFile), strings.TrimSpace(keyFile))
	if err != nil {
		return fmt.Errorf("load syslog TLS keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if caPath := strings.TrimSpace(clientCAFile); caPath != "" {
		pemBytes, caErr := os.ReadFile(caPath)
		if caErr != nil {
			return fmt.Errorf("read syslog client CA %s: %w", caPath, caErr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return fmt.Errorf("no valid PEM certificates found in -syslog-tls-client-ca %s", caPath)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	ln, err := tls.Listen("tcp", cleanAddr, tlsCfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
					if hErr := tc.Handshake(); hErr != nil {
						_ = tc.Close()
						return
					}
				}
				s.serveConn(c)
			}(conn)
		}
	}()
	return nil
}
