//go:build linux

// portline-gateway is the Linux server for Portline Tunnel v1.
// It uses a Linux TUN device and a private TLS 1.3 IPv4 packet stream.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"

	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"syscall"
	"time"
	"unsafe"

	"portline/internal/ptunnel"
)

const gatewayVersion = "1.4.0"

type Config struct {
	Version     int    `json:"version"`
	Port        int    `json:"port"`
	Host        string `json:"host"`
	Token       string `json:"token"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

func main() {
	mode := flag.String("mode", "", "init | serve | check | export | version")
	config := flag.String("config", "/etc/portline/gateway.json", "configuration file")
	host := flag.String("host", "", "public IP or hostname")
	port := flag.Int("port", 443, "TCP port")
	flag.Parse()
	var err error
	switch *mode {
	case "init":
		err = provision(*config, *host, *port)
	case "serve":
		err = serve(*config)
	case "check":
		_, err = loadConfig(*config)
	case "export":
		err = exportProfile(*config)
	case "version":
		fmt.Println("PORTLINE_VERSION=" + gatewayVersion)
	default:
		err = errors.New("expected -mode init, serve, check, export or version")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func loadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.Version != 1 || c.Port < 1 || c.Port > 65535 {
		return c, errors.New("invalid gateway configuration")
	}
	token, err := base64.RawURLEncoding.DecodeString(c.Token)
	if err != nil || len(token) != 32 {
		return c, errors.New("invalid gateway token")
	}
	if _, err = tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey)); err != nil {
		return c, err
	}
	return c, nil
}

func provision(path, host string, port int) error {
	if host == "" {
		return errors.New("public host is required")
	}
	// Validate host/port before doing filesystem or network changes.
	tempKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	validation := ptunnel.Profile{Version: 1, Host: host, Port: port, Token: tempKey, ServerKeyPin: tempKey}
	if err := validation.Validate(); err != nil {
		return err
	}
	c, err := loadConfig(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("existing server config invalid: %w", err)
	}
	needGenerate := os.IsNotExist(err)
	if !needGenerate {
		if kp, kerr := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey)); kerr == nil && len(kp.Certificate) > 0 {
			if leaf, lerr := x509.ParseCertificate(kp.Certificate[0]); lerr == nil && leaf.PublicKeyAlgorithm == x509.Ed25519 {
				_ = os.Remove(path)
				needGenerate = true
			}
		}
	}
	if needGenerate {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return err
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Portline Tunnel Server"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(3, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = []net.IP{ip}
		} else {
			template.DNSNames = []string{host}
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
		if err != nil {
			return err
		}
		pemKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
		token := make([]byte, 32)
		if _, err = rand.Read(token); err != nil {
			return err
		}
		c = Config{Version: 1, Port: port, Host: host, Token: base64.RawURLEncoding.EncodeToString(token), Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pemKey}))}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		data, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		// O_EXCL avoids overwriting the existing server identity on a retry.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	} else if c.Port != port || c.Host != host {
		return fmt.Errorf("gateway already configured on %s:%d; not replacing its identity", c.Host, c.Port)
	}
	return exportProfile(path)
}

// exportProfile reads an existing identity without changing it. Only call this
// from an authenticated, privileged SSH session. Output contains a secret.
func exportProfile(path string) error {
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	profile := ptunnel.Profile{Version: 1, Host: c.Host, Port: c.Port, ServerKeyPin: ptunnel.PinCertificate(leaf), Token: c.Token}
	encoded, err := ptunnel.EncodeProfile(profile)
	if err != nil {
		return err
	}
	fmt.Println("PORTLINE_TUNNEL_PROFILE=" + encoded)
	return nil
}

func command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func enableRouting(ctx context.Context) (func(), error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("gateway requires Linux")
	}
	// IP forwarding is a host-wide setting. We deliberately never undo it,
	// since existing workloads may rely on it.
	if err := command(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return nil, err
	}
	outbound, err := exec.Command("sh", "-c", "ip -4 route show default | head -n 1").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(outbound))
	device := ""
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			device = fields[i+1]
			break
		}
	}
	if device == "" {
		return nil, errors.New("no default IPv4 network interface found")
	}
	if err = command(ctx, "ip", "addr", "replace", ptunnel.ServerIP+"/16", "dev", "portline0"); err != nil {
		return nil, err
	}
	if err = command(ctx, "ip", "link", "set", "portline0", "mtu", strconv.Itoa(ptunnel.MTU), "up"); err != nil {
		return nil, err
	}
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", ptunnel.Subnet, "-o", device, "-j", "MASQUERADE"},
		{"FORWARD", "-i", "portline0", "-o", device, "-j", "ACCEPT"},
		{"FORWARD", "-i", device, "-o", "portline0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	installed := [][]string{}
	undo := func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for i := len(installed) - 1; i >= 0; i-- {
			args := append([]string{"-D"}, installed[i]...)
			if len(installed[i]) > 0 && installed[i][0] == "-t" {
				args = append([]string{"-t", "nat", "-D"}, installed[i][2:]...)
			}
			_ = command(cleanCtx, "iptables", args...)
		}
	}
	for _, rule := range rules {
		args := append([]string{"-A"}, rule...)
		if rule[0] == "-t" {
			args = append([]string{"-t", "nat", "-A"}, rule[2:]...)
		}
		if err = command(ctx, "iptables", args...); err != nil {
			undo()
			return nil, err
		}
		installed = append(installed, rule)
	}
	return undo, nil
}

const tunSetIFF = 0x400454ca
const iffTun = 0x0001
const iffNoPI = 0x1000

func newTun() (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening Linux TUN: %w", err)
	}
	var req [40]byte
	copy(req[:16], []byte("portline0"))
	req[16] = byte((iffTun | iffNoPI) & 0xff)
	req[17] = byte((iffTun | iffNoPI) >> 8)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		_ = f.Close()
		return nil, errno
	}
	return f, nil
}

func serve(path string) error {
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	tun, err := newTun()
	if err != nil {
		return err
	}
	defer tun.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	undo, err := enableRouting(ctx)
	if err != nil {
		return err
	}
	defer undo()
	certificate, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", c.Port), &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{ptunnel.LeaseProtocol}, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	log.Printf("Portline Tunnel started on TCP %d", c.Port)
	var peers peerTable
	go func() {
		buf := make([]byte, ptunnel.MTU)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				return
			}
			peers.deliver(buf[:n])
		}
	}()
	expected, err := base64.RawURLEncoding.DecodeString(c.Token)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go peers.handle(conn.(*tls.Conn), expected, tun)
	}
}
