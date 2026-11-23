package ptunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func makePacket() []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[12:16], []byte{10, 76, 24, 2})
	copy(pkt[16:20], []byte{1, 1, 1, 1})
	return pkt
}
func TestRoundtripPacket(t *testing.T) {
	p := makePacket()
	var b bytes.Buffer
	if err := WritePacket(&b, p); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPacket(&b, make([]byte, MTU))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, p) {
		t.Fatal("mismatched packet")
	}
	if !SourceIs(got, ClientIP) {
		t.Fatal("source check")
	}
}
func TestRejectMalformed(t *testing.T) {
	for _, p := range [][]byte{nil, []byte{0x60}, make([]byte, MTU+1)} {
		var b bytes.Buffer
		if err := WritePacket(&b, p); err == nil {
			t.Fatal("accepted invalid packet")
		}
	}
	var b bytes.Buffer
	b.Write([]byte{0xff, 0xff})
	if _, err := ReadPacket(&b, make([]byte, MTU)); err == nil {
		t.Fatal("accepted invalid length")
	}
}
func TestProfileValidation(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	p := Profile{Version: 1, Host: "203.0.113.4", Port: 443, Token: base64.RawURLEncoding.EncodeToString(key), ServerKeyPin: base64.RawURLEncoding.EncodeToString(key)}
	encoded, err := EncodeProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeProfile(encoded)
	if err != nil || got.Host != p.Host {
		t.Fatalf("%v %v", got, err)
	}
	p.Host = "bad host;"
	if err := p.Validate(); err == nil {
		t.Fatal("accepted shell input")
	}
	if _, err := DecodeProfile(strings.Repeat("a", 10000)); err == nil {
		t.Fatal("accepted oversized profile")
	}
}

type shortWriter struct{ count int }

func (w *shortWriter) Write(p []byte) (int, error) {
	w.count++
	if w.count == 1 {
		return 1, nil
	}
	return len(p), nil
}

func TestFrameRejectsShortHeaderWrite(t *testing.T) {
	if err := WritePacket(&shortWriter{}, makePacket()); err != io.ErrShortWrite {
		t.Fatalf("expected short-write error, got %v", err)
	}
}
