package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"portline/internal/ptunnel"
	"strconv"
	"strings"
	"time"
)

// Allow only the loopback hosts that the local application UI actually uses.
// This closes a DNS-rebinding route to the bearer token embedded in index.html.
func localHostOnly(hostPort string) bool {
	hostname := hostPort
	if strings.Contains(hostPort, ":") {
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			return false
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
		hostname = host
	}
	return hostname == "127.0.0.1" || hostname == "localhost"
}

func (a *App) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !localHostOnly(r.Host) {
		http.Error(w, "Invalid host", http.StatusForbidden)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page, _ := assets.ReadFile("ui/index.html")
		// token is hexadecimal; safe in a quoted HTML attribute.
		page = []byte(strings.NewReplacer("%%TOKEN%%", a.token, "%%VERSION%%", version).Replace(string(page)))
		_, _ = w.Write(page)
		return
	}
	if r.URL.Path == "/style.css" || r.URL.Path == "/app.js" {
		path := "ui/" + strings.TrimPrefix(r.URL.Path, "/")
		data, err := assets.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(path, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		}
		_, _ = w.Write(data)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if !strings.EqualFold(r.Header.Get("Authorization"), "Bearer "+a.token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch r.URL.Path {
	case "/api/status":
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		a.mu.Lock()
		a.lastAccess = time.Now()
		s := a.status
		s.Logs = append([]string(nil), s.Logs...)
		if a.nativeSession != nil {
			s.Tunnel.SentPackets = a.nativeSession.sent.Load()
			s.Tunnel.ReceivedPackets = a.nativeSession.received.Load()
			s.Tunnel.LatencyMs = a.nativeSession.latencyMs.Load()
			s.Tunnel.ConnectedAt = a.tunnelConnectedAt
			s.Tunnel.GuardMode = a.nativeSession.guardMode
		}
		a.mu.Unlock()
		s.TunnelLogs = a.snapshotTunnelLogs()
		_ = json.NewEncoder(w).Encode(s)
	case "/api/install":
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var data InstallRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&data); err != nil {
			http.Error(w, "Некорректный запрос", 400)
			return
		}
		if err := validate(data); err != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		a.mu.Lock()
		if a.busy || a.portBusy || a.gatewayBusy {
			a.mu.Unlock()
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Установка уже выполняется."})
			return
		}
		a.busy = true
		a.started = true
		a.lastAccess = time.Now()
		a.status = AppStatus{State: "running", Phase: "Соединение с сервером", Progress: 5, Logs: []string{}, Protocol: data.Protocol, Host: data.Host, Started: time.Now().Format(time.RFC3339), HAPP: HAPPTask{State: "idle"}}
		a.mu.Unlock()
		go a.install(data)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})
	case "/api/ports/check", "/api/ports/stop":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var input PortStopRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&input); err != nil {
			http.Error(w, "Некорректный запрос", http.StatusBadRequest)
			return
		}
		if err := validate(input.InstallRequest); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		action := "check"
		if r.URL.Path == "/api/ports/stop" {
			action = "stop"
		}
		a.mu.Lock()
		if a.busy || a.portBusy || a.gatewayBusy {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Дождись завершения текущей операции на VPS."})
			return
		}
		identity := portIdentity(input.InstallRequest)
		if action == "stop" && (a.portKey != identity ||
			a.status.PortTask.State != "busy" || !a.status.PortTask.CanStop ||
			a.status.PortTask.Service != input.Service || input.Service == "") {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Сначала проверь этот порт и убедись, что служба не изменилась."})
			return
		}
		a.portBusy = true
		a.portKey = identity
		a.lastAccess = time.Now()
		a.status.PortTask = PortTask{State: "running", Protocol: input.Protocol, Port: input.Port, Message: "Подключаемся к VPS и проверяем порт…"}
		if action == "stop" {
			a.status.PortTask.Message = "Останавливаем выбранную службу…"
		}
		a.mu.Unlock()
		go a.runPortTask(input.InstallRequest, action, input.Service)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})
	case "/api/tunnel/profile/export", "/api/tunnel/profile/import":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", 405)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if r.URL.Path == "/api/tunnel/profile/export" {
			encoded, err := ptunnel.EncodeProfile(a.tunnelProfile)
			if err != nil || !a.status.HasNativeProfile {
				http.Error(w, "Missing tunnel profile", 409)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"profile": encoded})
			return
		}
		if a.nativeSession != nil || a.tunnelBusy || a.gatewayBusy || a.busy || a.portBusy {
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(map[string]string{"error": "Заверши текущую операцию и отключи VPN перед импортом."})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		if err != nil {
			http.Error(w, "Invalid profile size", 400)
			return
		}
		p, err := ptunnel.DecodeProfile(strings.TrimSpace(string(raw)))
		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "Некорректный файл профиля Portline."})
			return
		}
		if err = saveTunnelProfile(p); err != nil {
			http.Error(w, "Cannot save tunnel profile", 500)
			return
		}
		a.tunnelProfile = p
		a.status.HasNativeProfile = true
		a.status.NativeProfileHost = p.Host
		a.status.NativeProfilePort = p.Port
		a.status.NeedsFreshProfile = false
		a.status.Host = p.Host
		a.status.Protocol = "portline"
		a.status.State = "success"
		a.status.Phase = "Профиль импортирован"
		a.status.Progress = 100
		a.status.Tunnel = TunnelTask{State: "idle", Message: "Профиль готов к подключению."}
		json.NewEncoder(w).Encode(map[string]bool{"imported": true})
	case "/api/tunnel/diagnose":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.mu.Lock()
		if session := a.nativeSession; session != nil && !a.tunnelBusy {
			endpoint := a.tunnelProfile.Endpoint()
			sent, received := session.sent.Load(), session.received.Load()
			a.mu.Unlock()
			result := TunnelProbe{State: "pending", Stage: "traffic", Endpoint: endpoint, Message: fmt.Sprintf("Пакеты IPv4 с начала подключения: отправлено %d, получено %d.", sent, received), Advice: "Открой сайт и повтори проверку, чтобы увидеть изменение счётчиков."}
			if sent > 0 && received > 0 {
				result.State = "ok"
			}
			json.NewEncoder(w).Encode(result)
			return
		}
		if a.tunnelBusy {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Диагностика без изменения маршрутов доступна только при отключённом туннеле."})
			return
		}
		if !a.status.HasNativeProfile {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Сначала импортируйте профиль действующего Gateway через SSH."})
			return
		}
		profile := a.tunnelProfile
		a.lastAccess = time.Now()
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(probePortline(r.Context(), profile))
	case "/api/tunnel/connect", "/api/tunnel/disconnect":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		action := "connect"
		if r.URL.Path == "/api/tunnel/disconnect" {
			action = "disconnect"
		}
		var target struct {
			ExpectedHost string `json:"expectedHost"`
			ExpectedPort int    `json:"expectedPort"`
		}
		if action == "connect" && r.ContentLength > 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&target); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Не удалось прочитать выбранный сервер."})
				return
			}
		}
		a.mu.Lock()
		if action == "disconnect" && a.wantConnected && a.tunnelBusy {
			a.wantConnected = false
			a.status.Tunnel = TunnelTask{State: "disconnecting", Phase: "Отключение туннеля…", Message: "Отменяем переподключение и восстанавливаем сеть…"}
			a.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})
			return
		}
		if a.tunnelBusy {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Операция с туннелем уже выполняется."})
			return
		}
		if action == "connect" && a.nativeSession != nil {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Туннель уже подключён. Сначала отключи его."})
			return
		}
		if action == "connect" && (target.ExpectedHost != "" || target.ExpectedPort != 0) &&
			(target.ExpectedHost != a.tunnelProfile.Host || target.ExpectedPort != a.tunnelProfile.Port) {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("В форме указан %s:%d, а сохранённый VPN-профиль использует %s:%d. Portline не будет подключаться к другому серверу или порту. Открой «Проверить Gateway» → «Использовать существующий сервер», чтобы получить актуальный профиль.", target.ExpectedHost, target.ExpectedPort, a.tunnelProfile.Host, a.tunnelProfile.Port)})
			return
		}
		if action == "connect" && !a.status.HasNativeProfile {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Сначала установи Portline Tunnel на VPS."})
			return
		}
		a.tunnelBusy = true
		if action == "disconnect" {
			a.status.Tunnel = TunnelTask{State: "disconnecting", Phase: "Отключение туннеля…", Message: "Разрываем соединение, очищаем правила и восстанавливаем DNS…"}
		} else {
			a.status.Tunnel = TunnelTask{State: "running", Phase: "Подготовка туннеля Portline"}
		}
		a.lastAccess = time.Now()
		a.mu.Unlock()
		go a.runTunnelTask(action)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})
	case "/api/gateway/inspect", "/api/gateway/use", "/api/gateway/update":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		action := strings.TrimPrefix(r.URL.Path, "/api/gateway/")
		var req InstallRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "Некорректный запрос", http.StatusBadRequest)
			return
		}
		if action == "update" && !req.ConfirmUpdate {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Обновление требует отдельного подтверждения пользователя."})
			return
		}
		if req.Protocol != "portline" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Для работы с Gateway выбери Portline Tunnel."})
			return
		}
		if err := validate(req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		a.mu.Lock()
		if a.busy || a.portBusy || a.gatewayBusy || a.tunnelBusy {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Заверши текущую операцию с Gateway или туннелем."})
			return
		}
		if action != "inspect" && (a.status.Gateway.State != "installed" || !a.status.Gateway.Compatible || a.status.Gateway.Host != req.Host || a.status.Gateway.Port != strconv.Itoa(req.Port)) {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Сначала проверь Gateway. Адрес, порт и версия конфигурации должны совпадать."})
			return
		}
		if action == "update" && !a.status.Gateway.NeedsUpdate {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Обновление не требуется или несовместимо."})
			return
		}
		if action == "use" && a.status.Gateway.Activity != "active" {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Служба Gateway не активна; сначала восстанови её."})
			return
		}
		a.gatewayBusy = true
		a.status.GatewayAction = "running"
		a.status.GatewayError = ""
		if action == "inspect" {
			a.status.Gateway = GatewayInspection{}
		}
		if action == "use" {
			a.installProfileSeen = false
		}
		a.lastAccess = time.Now()
		a.mu.Unlock()
		go a.runGatewayAction(req, action)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})
	case "/api/firewall/enable":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Confirm bool `json:"confirm"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body)
		if !body.Confirm {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Включение брандмауэра требует подтверждения пользователя."})
			return
		}
		a.mu.Lock()
		if a.tunnelBusy || a.nativeSession != nil {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Дождись завершения операции с туннелем."})
			return
		}
		a.lastAccess = time.Now()
		a.mu.Unlock()
		if err := enableFirewall(r.Context()); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Не удалось включить брандмауэр Windows. Включи его вручную: Параметры → Безопасность Windows → Брандмауэр и защита сети."})
			return
		}
		a.modify(func(s *AppStatus) {
			s.Tunnel = TunnelTask{State: "idle", Message: "Брандмауэр Windows включён. Можно подключаться."}
		})
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	case "/api/happ-install":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.mu.Lock()
		if a.status.State != "success" || a.status.Link == "" {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Сначала заверши настройку VPS."})
			return
		}
		if a.happBusy {
			a.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Установка HAPP уже выполняется."})
			return
		}
		a.happBusy = true
		a.lastAccess = time.Now()
		a.status.HAPP = HAPPTask{State: "running", Phase: "Подготовка установки HAPP"}
		a.mu.Unlock()
		go a.runHAPPInstall()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})

	case "/api/profiles":
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"profiles": a.listServerProfiles(), "passwordStorage": secretsStorageDescription()})
		case http.MethodPost:
			var input saveProfileRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&input); err != nil {
				http.Error(w, "Некорректный запрос", http.StatusBadRequest)
				return
			}
			profile, err := a.saveServerProfile(input)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"profile": profile, "profiles": a.listServerProfiles(), "passwordStorage": secretsStorageDescription()})
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if err := a.deleteServerProfile(id); err != nil {
				if os.IsNotExist(err) {
					http.Error(w, "Профиль не найден", http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"profiles": a.listServerProfiles(), "passwordStorage": secretsStorageDescription()})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "/api/profiles/load":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		profile, err := a.loadServerProfile(r.URL.Query().Get("id"))
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "Профиль не найден", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"profile": profile})
	case "/api/logs/clear":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.clearTunnelLogs()
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	case "/api/update":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.mu.Lock()
		a.lastAccess = time.Now()
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(checkGitHubUpdate(r.Context()))
	case "/api/update/install":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := a.installSelfUpdate(r.Context()); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true, "restarting": true})
	case "/api/quit":
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		a.mu.Lock()
		busy := a.busy || a.happBusy || a.portBusy || a.tunnelBusy || a.gatewayBusy
		a.mu.Unlock()
		if busy {
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Пока выполняется установка, выход заблокирован."})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		go func() { time.Sleep(150 * time.Millisecond); a.requestQuit() }()
	default:
		http.NotFound(w, r)
	}
}
