//go:build linux

package main

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"path/filepath"
	"portline/internal/ptunnel"
	"testing"
	"time"
)

func TestPeersDeliverOnlyToAddressOwner(t *testing.T) {
	var peers peerTable
	legacy := peers.reserve(false)
	first := peers.reserve(true)
	second := peers.reserve(true)
	if legacy == nil || first == nil || second == nil || first.ip == second.ip || peers.reserve(false) != nil {
		t.Fatal("lease collision")
	}
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[16:], net.ParseIP(second.ip).To4())
	peers.deliver(packet)
	select {
	case <-second.queue:
	default:
		t.Fatal("reply lost")
	}
	if len(first.queue) != 0 || len(legacy.queue) != 0 {
		t.Fatal("reply leaked to another peer")
	}
	peers.release(second)
	if p := peers.reserve(true); p == nil || p.ip != second.ip {
		t.Fatal("lease not released")
	}
}

type testTun chan []byte

func (tun testTun) Write(p []byte) (int, error) { tun <- append([]byte(nil), p...); return len(p), nil }

func TestSamePortTwoClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	encoded, err := captureProvision(t, path, "127.0.0.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ptunnel.DecodeProfile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(cfg.Certificate), []byte(cfg.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{ptunnel.LeaseProtocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	token, _ := base64.RawURLEncoding.DecodeString(profile.Token)
	var table peerTable
	tun := make(testTun, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go table.handle(c.(*tls.Conn), token, tun)
		}
	}()
	connect := func(legacy bool) (net.Conn, net.IP) {
		t.Helper()
		conf, err := profile.TLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		if legacy {
			conf.NextProtos = nil
		}
		c, err := tls.Dial("tcp", l.Addr().String(), conf)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write(token); err != nil {
			t.Fatal(err)
		}
		var ack [1]byte
		if _, err = io.ReadFull(c, ack[:]); err != nil || ack[0] != 1 {
			t.Fatal("missing ack", err)
		}
		ip := net.ParseIP(ptunnel.ClientIP).To4()
		if !legacy {
			if _, err = io.ReadFull(c, ip); err != nil {
				t.Fatal(err)
			}
		}
		return c, ip
	}
	a, ipA := connect(false)
	b, ipB := connect(false)
	_, legacyIP := connect(true)
	if ipA.Equal(ipB) || ipA.Equal(legacyIP) || ipB.Equal(legacyIP) {
		t.Fatal("duplicate address")
	}
	packet := func(src, dst net.IP) []byte {
		p := make([]byte, 20)
		p[0] = 0x45
		p[3] = 20
		copy(p[12:16], src.To4())
		copy(p[16:20], dst.To4())
		return p
	}
	remote := net.IPv4(203, 0, 113, 9)
	for _, client := range []struct {
		c  net.Conn
		ip net.IP
	}{{a, ipA}, {b, ipB}} {
		if err := ptunnel.WritePacket(client.c, packet(client.ip, remote)); err != nil {
			t.Fatal(err)
		}
		select {
		case pkt := <-tun:
			if !ptunnel.SourceIs(pkt, client.ip.String()) {
				t.Fatal("incorrect upstream address")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no upstream packet")
		}
	}
	table.deliver(packet(remote, ipB))
	table.deliver(packet(remote, ipA))
	for _, client := range []struct {
		c  net.Conn
		ip net.IP
	}{{a, ipA}, {b, ipB}} {
		pkt, err := ptunnel.ReadPacket(client.c, make([]byte, ptunnel.MTU))
		if err != nil || !ptunnel.DestinationIs(pkt, client.ip.String()) {
			t.Fatal("misdirected reply", err)
		}
	}
	if err := ptunnel.WritePacket(a, packet(ipB, remote)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("spoofed sender should be disconnected, got %v", err)
	}
}

func TestPeersScaleBeyond254(t *testing.T) {
	var peers peerTable
	seen := make(map[string]bool)
	allocated := make([]*peer, 0, 400)
	for i := 0; i < 400; i++ {
		p := peers.reserve(true)
		if p == nil {
			t.Fatalf("failed to allocate peer %d", i)
		}
		if !ptunnel.ValidClientIP(p.ip) {
			t.Fatalf("invalid allocated ip %s", p.ip)
		}
		if seen[p.ip] {
			t.Fatalf("duplicate allocated ip %s", p.ip)
		}
		seen[p.ip] = true
		allocated = append(allocated, p)
	}
	for _, p := range allocated {
		peers.release(p)
	}
}
