//go:build linux

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"portline/internal/ptunnel"
)

func captureProvision(t *testing.T, path string, host string, port int) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	provisionErr := provision(path, host, port)
	writer.Close()
	os.Stdout = original
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(content)), "PORTLINE_TUNNEL_PROFILE=")), provisionErr
}
func TestProvisionIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	first, err := captureProvision(t, path, "203.0.113.9", 8443)
	if err != nil {
		t.Fatal(err)
	}
	second, err := captureProvision(t, path, "203.0.113.9", 8443)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("credentials changed on retry")
	}
	_, err = captureProvision(t, path, "203.0.113.9", 9443)
	if err == nil {
		t.Fatal("server silently changed port")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("insecure permissions: %v", stat.Mode())
	}
	p, err := ptunnel.DecodeProfile(first)
	if err != nil || p.Port != 8443 {
		t.Fatalf("profile not valid: %v", err)
	}
}
func TestTLSHandshakeAndPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	encoded, err := captureProvision(t, path, "127.0.0.1", 8443)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ptunnel.DecodeProfile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if ptunnel.PinCertificate(leaf) != p.ServerKeyPin {
		t.Fatal("pin mismatch")
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outcome := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			outcome <- err
			return
		}
		defer peer.Close()
		token := make([]byte, 32)
		_, err = io.ReadFull(peer, token)
		outcome <- err
	}()
	config, err := p.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := tls.Dial("tcp", listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := base64.RawURLEncoding.DecodeString(p.Token)
	if _, err = client.Write(token); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err = <-outcome; err != nil {
		t.Fatal(err)
	}
	// A different public-key pin must fail the handshake.
	p.ServerKeyPin = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	wrongConfig, _ := p.TLSConfig()
	accepted := make(chan struct{})
	go func() {
		peer, e := listener.Accept()
		if e == nil {
			defer peer.Close()
			_ = peer.(*tls.Conn).Handshake()
		}
		close(accepted)
	}()
	peer, err := tls.Dial("tcp", listener.Addr().String(), wrongConfig)
	if err == nil {
		peer.Close()
		t.Fatal("accepted wrong server identity")
	}
	<-accepted
}
