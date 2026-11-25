package catalogue

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestZeroActiveProbingOrThirdPartyDependencies(t *testing.T) {
	gomod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if strings.Contains(string(gomod), "require") {
		t.Fatalf("expected zero external Go dependencies in go.mod, got:\n%s", string(gomod))
	}

	// Ensure no Go source file in this repository contains active endpoint probing logic
	for _, rel := range []string{"catalogue.go", "connectors.go", "../cmd/inferping-dns-collector/main.go"} {
		src, rErr := os.ReadFile(rel)
		if rErr != nil {
			t.Fatalf("read %s: %v", rel, rErr)
		}
		for _, forbidden := range []string{"chat/completions", "tools/list", "jsonrpc", "max_tokens"} {
			if strings.Contains(string(src), forbidden) {
				t.Fatalf("found forbidden active-probing token %q in %s", forbidden, rel)
			}
		}
	}
}

func TestWindowsADDNSAndEncryptedSyslogAndConnectors(t *testing.T) {
	if DomainCount() < 185 {
		t.Fatalf("expected >= 185 preloaded AI domains, got %d", DomainCount())
	}

	winLine := `25/11/2026 19:40:12 0B5C PACKET 0000021A UDP Rcv 10.24.8.51 4d2a Q [0001 D NOERROR] A (4)chat(8)deepseek(3)com(0)`
	sig, ok := MatchLine(winLine)
	if !ok || sig.ToolID != "deepseek-chat" {
		t.Fatalf("Windows AD DNS wire-label match failed: ok=%v sig=%+v", ok, sig)
	}

	multi := MatchAllLines(`{"src":"10.0.1.9","referer":"https://chatgpt.com/","dst":"fal.ai"}`)
	if len(multi) != 2 {
		t.Fatalf("expected 2 distinct tools, got %d", len(multi))
	}

	// RFC 5425 mTLS + RFC 6587 octet-counting syslog test
	tmpDir := t.TempDir()
	caPEM, srvCertPEM, srvKeyPEM, goodClient, badClient := makeTestCerts(t)
	caFile := filepath.Join(tmpDir, "ca.pem")
	srvCert := filepath.Join(tmpDir, "srv.pem")
	srvKey := filepath.Join(tmpDir, "srv.key")
	_ = os.WriteFile(caFile, caPEM, 0600)
	_ = os.WriteFile(srvCert, srvCertPEM, 0600)
	_ = os.WriteFile(srvKey, srvKeyPEM, 0600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pLn, _ := net.Listen("tcp", "127.0.0.1:0")
	tlsAddr := pLn.Addr().String()
	_ = pLn.Close()

	counter := NewCounter()
	if err := counter.ListenAndServeTLS(ctx, tlsAddr, srvCert, srvKey, caFile); err != nil {
		t.Fatalf("ListenAndServeTLS: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Untrusted client cert must be rejected
	if conn, bErr := tls.Dial("tcp", tlsAddr, &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{badClient}, ServerName: "localhost"}); bErr == nil {
		_, wErr := conn.Write([]byte("chat.deepseek.com\n"))
		var b [4]byte
		_, rErr := conn.Read(b[:])
		_ = conn.Close()
		if wErr == nil && rErr == nil {
			t.Fatalf("expected untrusted client cert to fail mTLS")
		}
	}

	// Trusted client sends RFC 6587 octet-counted frames
	goodConn, gErr := tls.Dial("tcp", tlsAddr, &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{goodClient}, ServerName: "localhost"})
	if gErr != nil {
		t.Fatalf("mTLS dial failed: %v", gErr)
	}
	f1 := `<134>1 2026-11-25T20:00:01Z fw dns - - qname=chat.deepseek.com srcip=10.1.2.3`
	f2 := `<134>1 2026-11-25T20:00:02Z dc1 dns - - Q A (3)api(7)mistral(2)ai(0)`
	_, _ = fmt.Fprintf(goodConn, "%d %s%d %s", len(f1), f1, len(f2), f2)
	_ = goodConn.Close()
	time.Sleep(50 * time.Millisecond)

	drained := counter.Drain()
	if drained["deepseek-chat"] != 1 || drained["mistral-api"] != 1 {
		t.Fatalf("unexpected mTLS counts: %+v", drained)
	}
	counter.Restore(drained)
	if restored := counter.Drain(); restored["deepseek-chat"] != 1 {
		t.Fatalf("Restore() failed: %+v", restored)
	}

	// Grafana Loki, Splunk, HTTP HEC, and Kafka tailer
	lokiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[{"values":[["1764096000000000001","10.1.1.5 query A baseten.co"]]}]}}`))
	}))
	defer lokiSrv.Close()
	lc, _, err := FetchLokiCounts(ctx, lokiSrv.URL, `{job="coredns"}`, "tok", "", time.Now().Add(-time.Minute), time.Now())
	if err != nil || lc["baseten-sambanova"] != 1 {
		t.Fatalf("FetchLokiCounts: err=%v counts=%+v", err, lc)
	}

	splunkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{\"result\":{\"_raw\":\"src=10.2.2.2 query=otter.ai\"}}\n"))
	}))
	defer splunkSrv.Close()
	sc, err := FetchSplunkCounts(ctx, splunkSrv.URL, "index=dns", "Splunk tok", "-60s", "now")
	if err != nil || sc["otter-ai"] != 1 {
		t.Fatalf("FetchSplunkCounts: err=%v counts=%+v", err, sc)
	}

	sinkCtr := NewCounter()
	sinkAddr, err := StartHTTPLogSink(ctx, "127.0.0.1:0", "sec99", sinkCtr)
	if err != nil {
		t.Fatalf("StartHTTPLogSink: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+sinkAddr+"/services/collector/event", strings.NewReader(`{"event":"query grok.com"}`))
	req.Header.Set("Authorization", "Splunk sec99")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("HEC push failed: %v", err)
	}
	_ = resp.Body.Close()
	if sc2 := sinkCtr.Drain(); sc2["xai-grok"] != 1 {
		t.Fatalf("HEC sink counts: %+v", sc2)
	}

	kAddr := startTestKafkaBroker(t, ctx, "dns-logs", `{"query":"chat.deepseek.com"}`)
	kCtr := NewCounter()
	if err := StartKafkaTailer(ctx, kAddr, "dns-logs", false, "", kCtr); err != nil {
		t.Fatalf("StartKafkaTailer: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var kc map[string]int
	for time.Now().Before(deadline) {
		kc = kCtr.Drain()
		if kc["deepseek-chat"] >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if kc["deepseek-chat"] < 1 {
		t.Fatalf("Kafka tailer counts: %+v", kc)
	}
}

func makeTestCerts(t *testing.T) (caPEM, srvCertPEM, srvKeyPEM []byte, goodClient, badClient tls.Certificate) {
	t.Helper()
	genCA := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &p.PublicKey, p)
		c, _ := x509.ParseCertificate(der)
		return c, p, encodePEM("CERTIFICATE", der)
	}
	caC, caK, caB := genCA("Trusted CA")
	badC, badK, _ := genCA("Untrusted CA")

	sp, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	sDER, _ := x509.CreateCertificate(rand.Reader, sTmpl, caC, &sp.PublicKey, caK)
	sKeyDER, _ := x509.MarshalECPrivateKey(sp)

	genClient := func(iss *x509.Certificate, ik *ecdsa.PrivateKey) tls.Certificate {
		cp, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "fw"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		cDER, _ := x509.CreateCertificate(rand.Reader, cTmpl, iss, &cp.PublicKey, ik)
		ckDER, _ := x509.MarshalECPrivateKey(cp)
		tc, _ := tls.X509KeyPair(encodePEM("CERTIFICATE", cDER), encodePEM("EC PRIVATE KEY", ckDER))
		return tc
	}
	return caB, encodePEM("CERTIFICATE", sDER), encodePEM("EC PRIVATE KEY", sKeyDER), genClient(caC, caK), genClient(badC, badK)
}

func encodePEM(typ string, der []byte) []byte {
	// Standard PEM encoding via stdlib encoding/pem inline helper
	var b bytes.Buffer
	b.WriteString("-----BEGIN " + typ + "-----\n")
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	enc := make([]byte, (len(der)+2)/3*4)
	di, si := 0, 0
	n := (len(der) / 3) * 3
	for si < n {
		val := uint(der[si+0])<<16 | uint(der[si+1])<<8 | uint(der[si+2])
		enc[di+0] = b64[val>>18&0x3F]
		enc[di+1] = b64[val>>12&0x3F]
		enc[di+2] = b64[val>>6&0x3F]
		enc[di+3] = b64[val&0x3F]
		si += 3
		di += 4
	}
	if rem := len(der) - si; rem > 0 {
		val := uint(der[si+0]) << 16
		if rem == 2 {
			val |= uint(der[si+1]) << 8
		}
		enc[di+0] = b64[val>>18&0x3F]
		enc[di+1] = b64[val>>12&0x3F]
		if rem == 2 {
			enc[di+2] = b64[val>>6&0x3F]
		} else {
			enc[di+2] = '='
		}
		enc[di+3] = '='
	}
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		b.Write(enc[i:end])
		b.WriteByte('\n')
	}
	b.WriteString("-----END " + typ + "-----\n")
	return b.Bytes()
}

func startTestKafkaBroker(t *testing.T, ctx context.Context, topic, recordJSON string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("kafka listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var portNum int
	_, _ = fmt.Sscanf(portStr, "%d", &portNum)
	go func() { <-ctx.Done(); _ = ln.Close() }()

	var mu sync.Mutex
	sent := false
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					var fl int32
					if binary.Read(conn, binary.BigEndian, &fl) != nil || fl < 8 {
						return
					}
					frame := make([]byte, fl)
					if _, err := io.ReadFull(conn, frame); err != nil {
						return
					}
					apiKey := int16(binary.BigEndian.Uint16(frame[0:2]))
					corrID := int32(binary.BigEndian.Uint32(frame[4:8]))
					var body bytes.Buffer
					switch apiKey {
					case 3:
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int16(len(host)))
						body.WriteString(host)
						_ = binary.Write(&body, binary.BigEndian, int32(portNum))
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int16(0))
						_ = binary.Write(&body, binary.BigEndian, int16(len(topic)))
						body.WriteString(topic)
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int16(0))
						_ = binary.Write(&body, binary.BigEndian, int32(0))
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int32(0))
						_ = binary.Write(&body, binary.BigEndian, int32(0))
					case 2:
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int16(len(topic)))
						body.WriteString(topic)
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int32(0))
						_ = binary.Write(&body, binary.BigEndian, int16(0))
						_ = binary.Write(&body, binary.BigEndian, int64(0))
						_ = binary.Write(&body, binary.BigEndian, int64(5))
					case 1:
						mu.Lock()
						first := !sent
						sent = true
						mu.Unlock()
						var ms []byte
						if first {
							ms = buildTestRecordBatch(5, []byte(recordJSON))
						} else {
							time.Sleep(40 * time.Millisecond)
						}
						_ = binary.Write(&body, binary.BigEndian, int32(0))
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int16(len(topic)))
						body.WriteString(topic)
						_ = binary.Write(&body, binary.BigEndian, int32(1))
						_ = binary.Write(&body, binary.BigEndian, int32(0))
						_ = binary.Write(&body, binary.BigEndian, int16(0))
						_ = binary.Write(&body, binary.BigEndian, int64(6))
						_ = binary.Write(&body, binary.BigEndian, int32(len(ms)))
						body.Write(ms)
					}
					var resp bytes.Buffer
					_ = binary.Write(&resp, binary.BigEndian, int32(4+body.Len()))
					_ = binary.Write(&resp, binary.BigEndian, corrID)
					resp.Write(body.Bytes())
					_, _ = conn.Write(resp.Bytes())
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func buildTestRecordBatch(baseOffset int64, val []byte) []byte {
	var rec bytes.Buffer
	rec.WriteByte(0)
	var tmp [10]byte
	rec.Write(tmp[:binary.PutVarint(tmp[:], 0)])
	rec.Write(tmp[:binary.PutVarint(tmp[:], 0)])
	rec.Write(tmp[:binary.PutVarint(tmp[:], -1)])
	rec.Write(tmp[:binary.PutVarint(tmp[:], int64(len(val)))])
	rec.Write(val)
	rec.Write(tmp[:binary.PutVarint(tmp[:], 0)])
	var framed bytes.Buffer
	framed.Write(tmp[:binary.PutVarint(tmp[:], int64(rec.Len()))])
	framed.Write(rec.Bytes())

	var batch bytes.Buffer
	_ = binary.Write(&batch, binary.BigEndian, int32(0))
	batch.WriteByte(2)
	_ = binary.Write(&batch, binary.BigEndian, uint32(0))
	_ = binary.Write(&batch, binary.BigEndian, uint16(0))
	_ = binary.Write(&batch, binary.BigEndian, int32(0))
	_ = binary.Write(&batch, binary.BigEndian, int64(0))
	_ = binary.Write(&batch, binary.BigEndian, int64(0))
	_ = binary.Write(&batch, binary.BigEndian, int64(-1))
	_ = binary.Write(&batch, binary.BigEndian, int16(-1))
	_ = binary.Write(&batch, binary.BigEndian, int32(-1))
	_ = binary.Write(&batch, binary.BigEndian, int32(1))
	batch.Write(framed.Bytes())

	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, baseOffset)
	_ = binary.Write(&out, binary.BigEndian, int32(batch.Len()))
	out.Write(batch.Bytes())
	return out.Bytes()
}
