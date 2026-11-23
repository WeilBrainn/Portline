//go:build linux

package main

import (
	"crypto/subtle"
	"crypto/tls"
	"io"
	"net"
	"portline/internal/ptunnel"
	"sync"
	"time"
)

type peer struct {
	ip    string
	queue chan []byte
}

type peerTable struct {
	mu    sync.Mutex
	slots map[uint16]*peer
}

func peerKey(octet3, octet4 byte) uint16 {
	return uint16(octet3)<<8 | uint16(octet4)
}

func isValidDynamicSlot(o3, o4 byte) bool {
	if o4 == 0 || o4 == 255 {
		return false
	}
	if o3 == 24 && (o4 == 1 || o4 == 2) {
		return false
	}
	return true
}

func (t *peerTable) reserve(dynamic bool) *peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.slots == nil {
		t.slots = make(map[uint16]*peer)
	}
	if !dynamic {
		key := peerKey(24, 2)
		if t.slots[key] != nil {
			return nil
		}
		p := &peer{ptunnel.ClientIP, make(chan []byte, 512)}
		t.slots[key] = p
		return p
	}
	// Allocate from 10.76.24.3..254 first, then wrap across 10.76.25.x..10.76.255.x and 10.76.0.x..10.76.23.x.
	for off := 0; off < 256; off++ {
		o3 := byte((24 + off) % 256)
		for o4 := 1; o4 <= 254; o4++ {
			if !isValidDynamicSlot(o3, byte(o4)) {
				continue
			}
			key := peerKey(o3, byte(o4))
			if t.slots[key] == nil {
				p := &peer{net.IPv4(10, 76, o3, byte(o4)).String(), make(chan []byte, 512)}
				t.slots[key] = p
				return p
			}
		}
	}
	return nil
}

func (t *peerTable) release(p *peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ip := net.ParseIP(p.ip).To4(); ip != nil {
		delete(t.slots, peerKey(ip[2], ip[3]))
	}
	close(p.queue)
}

func (t *peerTable) deliver(packet []byte) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[16] != 10 || packet[17] != 76 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.slots[peerKey(packet[18], packet[19])]
	if p == nil || !ptunnel.DestinationIs(packet, p.ip) {
		return
	}
	select {
	case p.queue <- append([]byte(nil), packet...):
	default:
	}
}

func (t *peerTable) handle(c *tls.Conn, expected []byte, tun io.Writer) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	token := make([]byte, 32)
	if _, err := io.ReadFull(c, token); err != nil || subtle.ConstantTimeCompare(token, expected) != 1 {
		return
	}
	dynamic := c.ConnectionState().NegotiatedProtocol == ptunnel.LeaseProtocol
	p := t.reserve(dynamic)
	if p == nil {
		return
	}
	defer t.release(p)
	ack := []byte{1}
	if dynamic {
		ack = append(ack, net.ParseIP(p.ip).To4()...)
	}
	if _, err := c.Write(ack); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	go func() {
		for packet := range p.queue {
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := ptunnel.WritePacket(c, packet); err != nil {
				c.Close()
				return
			}
		}
	}()
	buf := make([]byte, ptunnel.MTU)
	for {
		c.SetReadDeadline(time.Now().Add(90 * time.Second))
		pkt, err := ptunnel.ReadPacket(c, buf)
		if err != nil || !ptunnel.SourceIs(pkt, p.ip) {
			return
		}
		// Clients share credentials, but do not forward traffic between leases.
		if pkt[16] == 10 && pkt[17] == 76 && !(pkt[18] == 24 && pkt[19] == 1) {
			continue
		}
		if _, err := tun.Write(pkt); err != nil {
			return
		}
	}
}
