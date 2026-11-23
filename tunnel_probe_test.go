package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"portline/internal/ptunnel"
	"strings"
	"testing"
	"time"
)

func probeTestServer(t *testing.T, mode string) (ptunnel.Profile, func()) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Portline"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Portline"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	certPair := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: private}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if mode == "tcp-only" {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				tc := tls.Server(c, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certPair}})
				if tc.Handshake() != nil {
					return
				}
				var password [32]byte
				if _, err := io.ReadFull(tc, password[:]); err != nil {
					return
				}
				if mode == "accept" {
					_, _ = tc.Write([]byte{1})
				}
				if mode == "reject" {
					_, _ = tc.Write([]byte{0})
				}
			}()
		}
	}()
	address := raw.Addr().(*net.TCPAddr)
	profile := ptunnel.Profile{Version: 1, Host: address.IP.String(), Port: address.Port, Token: base64.RawURLEncoding.EncodeToString(tok), ServerKeyPin: ptunnel.PinCertificate(cert)}
	return profile, func() { raw.Close(); <-done }
}
func TestTunnelProbeReportsRealHandshakeStages(t *testing.T) {
	for _, tc := range []struct{ mode, stage, status string }{{"accept", "ready", "ok"}, {"reject", "auth", "error"}, {"tcp-only", "tls", "error"}} {
		t.Run(tc.mode, func(t *testing.T) {
			p, done := probeTestServer(t, tc.mode)
			defer done()
			ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
			defer cancel()
			r := probePortline(ctx, p)
			if r.Stage != tc.stage || r.State != tc.status {
				t.Fatalf("wanted %s/%s got %+v", tc.stage, tc.status, r)
			}
			if !strings.Contains(r.Endpoint, fmt.Sprint(p.Port)) {
				t.Fatalf("missing endpoint: %+v", r)
			}
		})
	}
}
func TestTunnelProbeRejectsInvalidIdentity(t *testing.T) {
	p, done := probeTestServer(t, "accept")
	defer done()
	p.ServerKeyPin = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	r := probePortline(context.Background(), p)
	if r.Stage != "identity" || r.State != "error" {
		t.Fatalf("unexpected: %+v", r)
	}
}
