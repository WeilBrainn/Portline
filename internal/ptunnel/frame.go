package ptunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Each TLS stream carries length-prefixed IP packets. The maximum tunnel MTU
// is intentionally conservative to avoid packet fragmentation.
func WritePacket(w io.Writer, data []byte) error {
	if len(data) < 20 || len(data) > MTU {
		return errors.New("packet size outside tunnel MTU")
	}
	if data[0]>>4 != 4 {
		return errors.New("only IPv4 packets are supported")
	}
	var frame [2 + MTU]byte
	binary.BigEndian.PutUint16(frame[:2], uint16(len(data)))
	copy(frame[2:], data)
	n, err := w.Write(frame[:2+len(data)])
	if err == nil && n != 2+len(data) {
		return io.ErrShortWrite
	}
	return err
}

func ReadPacket(r io.Reader, buf []byte) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n < 20 || n > MTU || n > len(buf) {
		return nil, errors.New("invalid tunnel packet length")
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	if buf[0]>>4 != 4 {
		return nil, errors.New("unsupported IP version")
	}
	ipHeaderSize := int(buf[0]&0x0f) * 4
	if ipHeaderSize < 20 || ipHeaderSize > n || int(binary.BigEndian.Uint16(buf[2:4])) != n {
		return nil, errors.New("malformed IPv4 packet")
	}
	return buf[:n], nil
}

func SourceIs(packet []byte, ip string) bool {
	return len(packet) >= 20 && net.IP(packet[12:16]).String() == ip
}
func DestinationIs(packet []byte, ip string) bool {
	return len(packet) >= 20 && net.IP(packet[16:20]).String() == ip
}
