package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

func (a *App) serveHTTP(w http.ResponseWriter, r *http.Request) {
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
		a.mu.Unlock()
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
		if a.busy || a.portBusy {
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
		if a.busy || a.portBusy {
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
	case "/api/quit":
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		a.mu.Lock()
		busy := a.busy || a.happBusy || a.portBusy
		a.mu.Unlock()
		if busy {
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Пока выполняется установка, выход заблокирован."})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		go func() { time.Sleep(150 * time.Millisecond); os.Exit(0) }()
	default:
		http.NotFound(w, r)
	}
}
