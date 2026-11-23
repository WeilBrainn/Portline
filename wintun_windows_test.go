package main

import (
	"context"
	"errors"
	"net"
	"portline/internal/ptunnel"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type fakeWintunProc func(...uintptr) (uintptr, uintptr, error)

func (f fakeWintunProc) Call(a ...uintptr) (uintptr, uintptr, error) { return f(a...) }

func TestWintunReadErrors(t *testing.T) {
	for _, code := range []syscall.Errno{syscall.ERROR_HANDLE_EOF, syscall.Errno(13), syscall.ERROR_ACCESS_DENIED} {
		t.Run(code.Error(), func(t *testing.T) {
			calls := 0
			d := &wintunDevice{receive: fakeWintunProc(func(...uintptr) (uintptr, uintptr, error) { calls++; return 0, 0, code })}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := d.ReadPacket(ctx)
			if !errors.Is(err, code) || calls != 1 {
				t.Fatalf("fatal receive error swallowed: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestWintunEmptyQueueRetriesUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	d := &wintunDevice{receive: fakeWintunProc(func(...uintptr) (uintptr, uintptr, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return 0, 0, syscall.Errno(259)
	})}
	_, err := d.ReadPacket(ctx)
	if !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestWintunSendQueueOverflowDropsPacket(t *testing.T) {
	d := &wintunDevice{allocate: fakeWintunProc(func(...uintptr) (uintptr, uintptr, error) { return 0, 0, syscall.Errno(111) })}
	if err := d.WritePacket(make([]byte, 20)); err != nil {
		t.Fatalf("full send ring disconnected tunnel: %v", err)
	}
}

func TestWintunWriteRejectsInvalidSizeAndPreservesFatalError(t *testing.T) {
	calls := 0
	d := &wintunDevice{allocate: fakeWintunProc(func(...uintptr) (uintptr, uintptr, error) { calls++; return 0, 0, syscall.ERROR_HANDLE_EOF })}
	for _, size := range []int{0, 1281} {
		if d.WritePacket(make([]byte, size)) == nil {
			t.Fatal("invalid size accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid packet reached Wintun")
	}
	if !errors.Is(d.WritePacket(make([]byte, 20)), syscall.ERROR_HANDLE_EOF) {
		t.Fatal("lost fatal write error")
	}
}

type failedPacketDevice struct{ closed bool }

func (*failedPacketDevice) ReadPacket(context.Context) ([]byte, error) {
	return nil, syscall.ERROR_HANDLE_EOF
}
func (*failedPacketDevice) WritePacket([]byte) error { return nil }
func (d *failedPacketDevice) Close()                 { d.closed = true }

func TestNativeSessionReadFailureStopsAndRestores(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &nativeSession{done: make(chan struct{}), stop: cancel}
	device := &failedPacketDevice{}
	restored := false
	failure := errors.New("rollback failed")
	go session.run(ctx, client, device, "10.76.24.2", func() error { restored = true; return failure })
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("receive failure left session connected")
	}
	if !device.closed || !restored || !errors.Is(session.CleanupError(), failure) {
		t.Fatal("missing teardown or rollback error")
	}
	// Repeated Stop must also complete after an unexpected failure.
	session.Stop()
	session.Stop()
}

type queuedPacketDevice struct{ packets chan []byte }

func (d *queuedPacketDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-d.packets:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*queuedPacketDevice) WritePacket([]byte) error { return nil }
func (*queuedPacketDevice) Close()                   {}

func TestNativeSessionDropsIPv6AndRecoversAfterPeerLoss(t *testing.T) {
	// A fresh session must work after the previous transport has failed.
	for attempt := 0; attempt < 2; attempt++ {
		client, peer := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		s := &nativeSession{done: make(chan struct{}), stop: cancel}
		d := &queuedPacketDevice{packets: make(chan []byte, 2)}
		d.packets <- []byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		ipv4 := make([]byte, 20)
		ipv4[0] = 0x45
		ipv4[3] = 20
		d.packets <- ipv4
		restored := false
		go s.run(ctx, client, d, "10.76.24.2", func() error { restored = true; return nil })
		peer.SetReadDeadline(time.Now().Add(time.Second))
		packet, err := ptunnel.ReadPacket(peer, make([]byte, 1280))
		peer.Close()
		if err != nil || len(packet) != 20 || packet[0] != 0x45 {
			cancel()
			t.Fatalf("IPv4 forwarding / IPv6 filtering: %x %v", packet, err)
		}
		select {
		case <-s.Done():
		case <-time.After(time.Second):
			cancel()
			t.Fatal("peer loss did not finish cleanup")
		}
		if !restored || s.CleanupError() != nil {
			t.Fatal("peer loss did not restore network")
		}
		cancel()
	}
}

func TestExcludeRangesAndICMPHelpers(t *testing.T) {
	if got := excludeIPv4Ranges("203.0.113.24"); got != "0.0.0.0-203.0.113.23,203.0.113.25-255.255.255.255" {
		t.Fatalf("unexpected IPv4 exclude ranges: %s", got)
	}
	if got := excludePortRanges(8443); got != "1-8442,8444-65535" {
		t.Fatalf("unexpected port exclude ranges: %s", got)
	}
	if got := excludePortRanges(443); got != "1-442,444-65535" {
		t.Fatalf("unexpected port 443 exclude ranges: %s", got)
	}

	// IPv6 TCP SYN -> ICMPv6 Type 1 Code 1 Admin Prohibited.
	v6 := make([]byte, 60)
	v6[0] = 0x60
	v6[6] = 6 // TCP
	v6[7] = 64
	copy(v6[8:24], net.ParseIP("fd76:24::2").To16())
	copy(v6[24:40], net.ParseIP("2606:4700:4700::1111").To16())
	reply, ok := buildICMPv6AdminProhibited(v6)
	if !ok || len(reply) != 48+60 || reply[6] != 58 || reply[40] != 1 || reply[41] != 1 {
		t.Fatalf("invalid ICMPv6 Admin Prohibited reply: ok=%v len=%d", ok, len(reply))
	}
	// Must not reply to ICMPv6 error packets.
	v6Err := make([]byte, 48)
	v6Err[0] = 0x60
	v6Err[6] = 58
	v6Err[40] = 1
	if _, ok := buildICMPv6AdminProhibited(v6Err); ok {
		t.Fatal("replied to ICMPv6 error packet")
	}

	req := buildICMPEchoRequest("10.76.24.2", "10.76.24.1", 7)
	if len(req) != 28 || req[20] != 8 {
		t.Fatalf("invalid echo request: %x", req)
	}
	// Turn into echo reply.
	req[20] = 0
	if seq, ok := isPortlineICMPEchoReply(req); !ok || seq != 7 {
		t.Fatalf("failed parsing echo reply: ok=%v seq=%d", ok, seq)
	}
}

func TestWFPStructSizesAMD64(t *testing.T) {
	if unsafe.Sizeof(wfpGUID{}) != 16 {
		t.Fatalf("wfpGUID size = %d", unsafe.Sizeof(wfpGUID{}))
	}
	if unsafe.Sizeof(fwpValue0{}) != 16 {
		t.Fatalf("fwpValue0 size = %d", unsafe.Sizeof(fwpValue0{}))
	}
	if unsafe.Sizeof(fwpmFilterCondition0{}) != 40 {
		t.Fatalf("fwpmFilterCondition0 size = %d", unsafe.Sizeof(fwpmFilterCondition0{}))
	}
	if unsafe.Sizeof(fwpmAction0{}) != 24 {
		t.Fatalf("fwpmAction0 size = %d", unsafe.Sizeof(fwpmAction0{}))
	}
	if unsafe.Sizeof(fwpmSession0{}) != 72 {
		t.Fatalf("fwpmSession0 size = %d", unsafe.Sizeof(fwpmSession0{}))
	}
	if unsafe.Sizeof(fwpmSublayer0{}) != 72 {
		t.Fatalf("fwpmSublayer0 size = %d", unsafe.Sizeof(fwpmSublayer0{}))
	}
	if unsafe.Sizeof(fwpmFilter0{}) != 200 {
		t.Fatalf("fwpmFilter0 size = %d", unsafe.Sizeof(fwpmFilter0{}))
	}
}
