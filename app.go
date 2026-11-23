package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"portline/internal/ptunnel"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type InstallRequest struct {
	ConfirmUpdate bool   `json:"confirmUpdate,omitempty"`
	Host          string `json:"host"`
	SSHPort       int    `json:"sshPort"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	KeyFile       string `json:"keyFile"`
	Auth          string `json:"auth"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
	SNI           string `json:"sni"`
}

type PortTask struct {
	State       string `json:"state"`
	Message     string `json:"message"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Process     string `json:"process"`
	PID         int    `json:"pid"`
	CanStop     bool   `json:"canStop"`
	Suggestions []int  `json:"suggestions"`
}

type PortStopRequest struct {
	InstallRequest
	Service string `json:"service"`
}

type TunnelTask struct {
	State           string `json:"state"`
	Phase           string `json:"phase"`
	Message         string `json:"message"`
	SentPackets     uint64 `json:"sentPackets,omitempty"`
	ReceivedPackets uint64 `json:"receivedPackets,omitempty"`
	LatencyMs       int64  `json:"latencyMs,omitempty"`
	ConnectedAt     string `json:"connectedAt,omitempty"`
	NeedsFirewall   bool   `json:"needsFirewall,omitempty"`
	GuardMode       string `json:"guardMode,omitempty"`
}

type HAPPTask struct {
	State   string `json:"state"`
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

type AppStatus struct {
	Gateway           GatewayInspection `json:"gateway"`
	GatewayAction     string            `json:"gatewayAction"`
	GatewayError      string            `json:"gatewayError"`
	State             string            `json:"state"`
	Phase             string            `json:"phase"`
	Progress          int               `json:"progress"`
	Logs              []string          `json:"logs"`
	Link              string            `json:"link"`
	HasNativeProfile  bool              `json:"hasNativeProfile"`
	NativeProfileHost string            `json:"nativeProfileHost"`
	NativeProfilePort int               `json:"nativeProfilePort"`
	Tunnel            TunnelTask        `json:"tunnel"`
	Error             string            `json:"error"`
	Protocol          string            `json:"protocol"`
	Host              string            `json:"host"`
	Started           string            `json:"started"`
	HAPP              HAPPTask          `json:"happ"`
	PortTask          PortTask          `json:"portTask"`
	PortConflict      bool              `json:"portConflict"`
	NeedsFreshProfile bool              `json:"needsFreshProfile"`
}

type App struct {
	gatewayBusy        bool
	mu                 sync.Mutex
	token              string
	status             AppStatus
	busy               bool
	happBusy           bool
	tunnelBusy         bool
	wantConnected      bool
	tunnelConnectedAt  string
	tunnelProfile      ptunnel.Profile
	nativeSession      *nativeSession
	portBusy           bool
	portKey            string
	lastAccess         time.Time
	started            bool
	savedServers       []SavedServer
	expectFreshProfile bool
	installProfileSeen bool
	quitCh             chan struct{}
	quitOnce           sync.Once
}

var errExistingInstanceNotified = errors.New("existing instance notified")

func (a *App) requestQuit() {
	a.quitOnce.Do(func() {
		if a.quitCh != nil {
			close(a.quitCh)
		}
	})
}

// Strip terminal control sequences before placing server output in the browser.
// The SSH stream is not a trusted display format.
var terminalEscapeRE = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

var hostRe = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var sniRe = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func validate(r InstallRequest) error {
	if !hostRe.MatchString(r.Host) || strings.Contains(r.Host, "..") || len(r.Host) > 253 {
		return errors.New("Укажи IPv4 или корректное DNS-имя VPS (без http:// и порта).")
	}
	if ip := net.ParseIP(r.Host); ip != nil && ip.To4() == nil {
		return errors.New("В этой версии поддерживаются IPv4 и DNS-имена. Для IPv6 нужен отдельный формат адреса.")
	}
	if r.SSHPort < 1 || r.SSHPort > 65535 || r.Port < 1 || r.Port > 65535 {
		return errors.New("Порт должен быть в диапазоне 1–65535.")
	}
	if !userRe.MatchString(r.Username) {
		return errors.New("Некорректное SSH-имя пользователя.")
	}
	if r.Auth != "password" && r.Auth != "key" {
		return errors.New("Выбери способ авторизации SSH.")
	}
	if r.Auth == "password" && (len(r.Password) < 1 || len(r.Password) > 1024) {
		return errors.New("Введи SSH-пароль сервера.")
	}
	if r.Auth == "key" {
		fi, err := os.Stat(r.KeyFile)
		if err != nil || fi.IsDir() {
			return errors.New("Файл SSH-ключа не найден на этом компьютере.")
		}
	}
	if r.Protocol != "vless" && r.Protocol != "hy2" && r.Protocol != "portline" {
		return errors.New("Выбери Portline Tunnel, VLESS + REALITY или Hysteria 2.")
	}
	if r.Protocol == "vless" && (!sniRe.MatchString(r.SNI) || strings.Contains(r.SNI, "..")) {
		return errors.New("Введи корректный TLS SNI, например www.cloudflare.com.")
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func (a *App) modify(fn func(*AppStatus)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(&a.status)
}

func (a *App) appendLog(line string) {
	line = terminalEscapeRE.ReplaceAllString(line, "")
	line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
	if strings.HasPrefix(line, "PORTLINE_GATEWAY|") {
		info, err := parseGatewayInspection(line)
		a.modify(func(s *AppStatus) {
			if err != nil {
				s.GatewayError = err.Error()
			} else {
				s.Gateway = info
			}
		})
		return
	}
	if strings.HasPrefix(line, profilePrefix) {
		if err := a.setTunnelProfile(strings.TrimPrefix(line, profilePrefix)); err != nil {
			a.modify(func(s *AppStatus) {
				s.Logs = append(s.Logs, "Не удалось сохранить конфигурацию: "+err.Error())
			})
		}
		return
	}
	if strings.Contains(line, profilePrefix) {
		return
	}
	if line == "" {
		return
	}
	// Profile transfer is base64 and intentionally longer than a log line.
	// Never show it in installation logs, including on validation failure.
	if len(line) > 500 {
		line = line[:500] + "…"
	}
	a.modify(func(s *AppStatus) {
		if strings.HasPrefix(line, "::phase|") {
			values := strings.SplitN(strings.TrimPrefix(line, "::phase|"), "|", 3)
			if len(values) == 2 {
				n, _ := strconv.Atoi(values[0])
				if n >= 0 && n <= 100 {
					s.Progress = n
				}
				s.Phase = values[1]
			}
			return
		}
		if strings.HasPrefix(line, "PORTLINE_PORT|") {
			if err := applyPortReport(&s.PortTask, line); err != nil {
				s.PortTask.State = "error"
				s.PortTask.Message = "Непонятный ответ проверки порта: " + err.Error()
			}
			return
		}
		if strings.HasPrefix(line, "PORTLINE_SUGGEST|") {
			s.PortTask.Suggestions = parsePortSuggestions(strings.TrimPrefix(line, "PORTLINE_SUGGEST|"))
			return
		}
		if strings.HasPrefix(line, "PORTLINE_LINK=") {
			s.Link = strings.TrimPrefix(line, "PORTLINE_LINK=")
			return
		}
		// Do not retain URIs from third-party installers accidentally printed to stdout.
		if strings.Contains(line, "vless://") || strings.Contains(line, "hysteria2://") || strings.Contains(line, "PrivateKey =") {
			return
		}
		if strings.Contains(line, " уже занят") && (strings.HasPrefix(line, "TCP ") || strings.HasPrefix(line, "UDP ")) {
			s.PortConflict = true
		}
		s.Logs = append(s.Logs, line)
		if len(s.Logs) > 90 {
			s.Logs = s.Logs[len(s.Logs)-90:]
		}
	})
}
