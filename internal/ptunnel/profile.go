// Package ptunnel contains Portline's transport framing and profile format.
// It deliberately does not implement cryptographic algorithms: connections use
// the Go TLS 1.3 implementation and pin the server certificate public key.
package ptunnel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const MTU = 1280
const LeaseProtocol = "portline-ipv4-lease/1"
const ClientIP = "10.76.24.2"
const ServerIP = "10.76.24.1"
const Subnet = "10.76.0.0/16"
const TunnelAlias = "Portline Tunnel"

// Profile is a credential. Never write it into logs or expose it in telemetry.
type Profile struct {
	Version      int    `json:"version"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ServerKeyPin string `json:"serverKeyPin"`
	Token        string `json:"token"`
}

var hostRE = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func (p Profile) Validate() error {
	if p.Version != 1 {
		return errors.New("unsupported Portline tunnel profile version")
	}
	if len(p.Host) > 253 || !hostRE.MatchString(p.Host) || strings.Contains(p.Host, "..") {
		return errors.New("invalid server hostname")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("invalid server port")
	}
	pin, err := base64.RawURLEncoding.DecodeString(p.ServerKeyPin)
	if err != nil || len(pin) != 32 {
		return errors.New("invalid server public key pin")
	}
	token, err := base64.RawURLEncoding.DecodeString(p.Token)
	if err != nil || len(token) != 32 {
		return errors.New("invalid authentication token")
	}
	return nil
}

func EncodeProfile(p Profile) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func DecodeProfile(encoded string) (Profile, error) {
	var p Profile
	encoded = strings.TrimSpace(encoded)
	encoded = strings.TrimPrefix(encoded, "portline://")
	if len(encoded) > 8192 {
		return p, errors.New("profile exceeds size limit")
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return p, err
	}
	if len(b) > 4096 {
		return p, errors.New("profile exceeds size limit")
	}
	if err = json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

// TLSConfig enforces TLS 1.3 and SHA-256 SPKI pinning. The certificate is
// self-signed at provisioning time, so platform trust is intentionally not used.
func (p Profile) TLSConfig() (*tls.Config, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	expected, _ := base64.RawURLEncoding.DecodeString(p.ServerKeyPin)
	return &tls.Config{
		NextProtos:         []string{LeaseProtocol},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by explicit SPKI verification below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server certificate missing")
			}
			actual := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !equal32(actual[:], expected) {
				return errors.New("server identity changed; tunnel stopped")
			}
			return nil
		},
	}, nil
}

func equal32(a, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func PinCertificate(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (p Profile) Endpoint() string { return net.JoinHostPort(p.Host, fmt.Sprint(p.Port)) }

func ValidClientIP(s string) bool {
	ip := net.ParseIP(s).To4()
	if ip == nil || ip.String() != s || ip[0] != 10 || ip[1] != 76 {
		return false
	}
	if (ip[2] == 24 && ip[3] == 1) || (ip[2] == 0 && ip[3] == 0) || (ip[2] == 255 && ip[3] == 255) {
		return false
	}
	return ip[3] != 0 && ip[3] != 255
}
