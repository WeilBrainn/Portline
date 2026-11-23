package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"portline/internal/ptunnel"
)

type tunnelTraffic struct {
	sent, received atomic.Uint64
	latencyMs      atomic.Int64
}

const profilePrefix = "PORTLINE_TUNNEL_PROFILE="

// A profile is a secret, so the public application status only exposes whether
// a profile exists. Only an explicit profile export returns the credential to the UI.
func (a *App) setTunnelProfile(encoded string) error {
	p, err := ptunnel.DecodeProfile(encoded)
	if err != nil {
		return err
	}
	if err := saveTunnelProfile(p); err != nil {
		return err
	}
	a.mu.Lock()
	a.tunnelProfile = p
	a.status.HasNativeProfile = true
	a.status.NativeProfileHost = p.Host
	a.status.NativeProfilePort = p.Port
	a.status.NeedsFreshProfile = false
	a.installProfileSeen = true
	a.mu.Unlock()
	return nil
}

func profilePath() (string, error) {
	root, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "profiles", "portline-tunnel.json"), nil
}

func saveTunnelProfile(p ptunnel.Profile) error {
	encoded, err := ptunnel.EncodeProfile(p)
	if err != nil {
		return err
	}
	path, err := profilePath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = lockProfileFile(tmp.Name()); err != nil {
		tmp.Close()
		return err
	}
	_, err = tmp.WriteString(encoded)
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), path)
}

func restoreTunnelProfile() (ptunnel.Profile, bool) {
	path, err := profilePath()
	if err != nil {
		return ptunnel.Profile{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ptunnel.Profile{}, false
	}
	p, err := ptunnel.DecodeProfile(strings.TrimSpace(string(b)))
	return p, err == nil
}

// A completed handshake and configured routes are required for the connected
// status. A TCP socket alone is not a system tunnel.
func (a *App) runTunnelTask(action string) {
	defer func() {
		if r := recover(); r != nil {
			a.mu.Lock()
			a.tunnelBusy = false
			a.wantConnected = false
			a.status.Tunnel = TunnelTask{State: "error", Message: fmt.Sprintf("Внутренняя ошибка туннеля: %v", r)}
			a.mu.Unlock()
			printlnPanic("runTunnelTask", r)
		}
	}()
	update := func(s string) {
		a.appendTunnelLog(s)
		a.modify(func(v *AppStatus) { v.Tunnel.Phase = s })
	}
	if action == "disconnect" {
		a.appendTunnelLog("Отключение туннеля…")
		a.mu.Lock()
		a.wantConnected = false
		old := a.nativeSession
		a.nativeSession = nil
		a.tunnelConnectedAt = ""
		a.mu.Unlock()
		var cleanupErr error
		if old != nil {
			old.Stop()
			cleanupErr = old.CleanupError()
		} else {
			cleanupErr = recoverStartupRoutes()
		}
		a.modify(func(v *AppStatus) {
			switch {
			case cleanupErr != nil:
				a.appendTunnelLog("Ошибка восстановления сети: " + cleanupErr.Error())
				v.Tunnel = TunnelTask{State: "error", Message: "Не удалось восстановить сеть: " + cleanupErr.Error()}
			case old == nil:
				a.appendTunnelLog("Активного соединения нет; маршруты проверены.")
				v.Tunnel = TunnelTask{State: "disconnected", Message: "Активного соединения нет; незавершённые изменения проверены."}
			default:
				a.appendTunnelLog("Туннель отключён, сеть восстановлена.")
				v.Tunnel = TunnelTask{State: "disconnected", Message: "Соединение отключено; сетевые маршруты восстановлены."}
			}
		})
		a.mu.Lock()
		a.tunnelBusy = false
		a.mu.Unlock()
		return
	}
	a.mu.Lock()
	a.wantConnected = true
	profile := a.tunnelProfile
	a.mu.Unlock()
	a.connectAndSupervise(profile, update)
}

func (a *App) connectAndSupervise(profile ptunnel.Profile, update func(string)) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	session, err := startNativeTunnel(ctx, profile, update)
	cancel()
	a.mu.Lock()
	a.tunnelBusy = false
	if err != nil {
		a.wantConnected = false
		msg := explainTunnelError(profile, err)
		a.appendTunnelLog("Ошибка подключения: " + msg)
		if errors.Is(err, errFirewallDisabled) {
			a.status.Tunnel = TunnelTask{State: "error", NeedsFirewall: true, Message: "Брандмауэр Windows выключен. Защита от утечек DNS, IPv6 и обхода через роутер работает через его правила, поэтому без него Portline не подключается. Сетевые настройки не изменялись. Включи брандмауэр кнопкой ниже — после отключения VPN он останется включённым."}
		} else {
			a.status.Tunnel = TunnelTask{State: "error", Message: msg}
		}
		a.mu.Unlock()
		return
	}
	if !a.wantConnected {
		a.mu.Unlock()
		session.Stop()
		return
	}
	a.nativeSession = session
	a.tunnelConnectedAt = time.Now().Format(time.RFC3339)
	a.status.Tunnel = connectedTask(session.guardMode, false)
	a.appendTunnelLog("Туннель подключён (режим защиты: " + session.guardMode + ")")
	a.mu.Unlock()
	go a.watchSession(session, profile, update)
}

func connectedTask(mode string, restored bool) TunnelTask {
	prefix := ""
	if restored {
		prefix = "Соединение восстановлено. "
	}
	if mode == "wfp" {
		return TunnelTask{State: "connected", Phase: "Полный туннель активен", GuardMode: "wfp",
			Message: prefix + "Весь трафик IPv4 и DNS защищён фильтрами WFP; IPv6 и прямые выходы (включая роутер) заблокированы."}
	}
	if mode == "routes" {
		return TunnelTask{State: "connected", Phase: "Полный туннель активен", GuardMode: "routes",
			Message: prefix + "Весь IPv4 идёт через сервер, DNS всех адаптеров направлен в туннель, IPv6 на Ethernet/Wi-Fi отключён. Брандмауэр выключен, поэтому защита только на маршрутах: при аварийном закрытии Portline трафик может пойти напрямую."}
	}
	return TunnelTask{State: "connected", Phase: "Полный туннель активен", GuardMode: "firewall",
		Message: prefix + "Весь трафик IPv4 и DNS защищён; IPv6 и прямые выходы заблокированы брандмауэром."}
}

func (a *App) watchSession(session *nativeSession, profile ptunnel.Profile, update func(string)) {
	<-session.Done()
	a.mu.Lock()
	if a.nativeSession != session {
		a.mu.Unlock()
		return
	}
	a.nativeSession = nil
	a.tunnelConnectedAt = ""
	cleanupErr := session.CleanupError()
	shouldReconnect := a.wantConnected && cleanupErr == nil
	if !shouldReconnect {
		a.wantConnected = false
		if cleanupErr != nil {
			a.status.Tunnel = TunnelTask{State: "error", Message: "Соединение прервалось. Сеть требует восстановления: " + cleanupErr.Error()}
		} else {
			a.status.Tunnel = TunnelTask{State: "error", Message: "Соединение прервалось. Маршруты восстановлены; подключись заново."}
		}
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	backoff := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second}
	for i, wait := range backoff {
		attempt := i + 1
		a.modify(func(v *AppStatus) {
			v.Tunnel = TunnelTask{
				State:   "running",
				Phase:   fmt.Sprintf("Переподключение (%d/%d)…", attempt, len(backoff)),
				Message: fmt.Sprintf("Связь с сервером прервалась. Восстанавливаем туннель (попытка %d из %d)…", attempt, len(backoff)),
			}
		})
		time.Sleep(wait)
		a.mu.Lock()
		if !a.wantConnected || a.nativeSession != nil || a.tunnelBusy {
			a.mu.Unlock()
			return
		}
		a.tunnelBusy = true
		a.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		nextSession, err := startNativeTunnel(ctx, profile, update)
		cancel()

		a.mu.Lock()
		a.tunnelBusy = false
		if err == nil {
			if !a.wantConnected {
				a.mu.Unlock()
				nextSession.Stop()
				return
			}
			a.nativeSession = nextSession
			a.tunnelConnectedAt = time.Now().Format(time.RFC3339)
			a.status.Tunnel = connectedTask(nextSession.guardMode, true)
			a.mu.Unlock()
			go a.watchSession(nextSession, profile, update)
			return
		}
		stillWanted := a.wantConnected
		a.mu.Unlock()
		if !stillWanted {
			return
		}
		if attempt == len(backoff) {
			a.modify(func(v *AppStatus) {
				v.Tunnel = TunnelTask{State: "error", Message: explainTunnelError(profile, err)}
			})
			a.mu.Lock()
			a.wantConnected = false
			a.mu.Unlock()
		}
	}
}

func printlnPanic(where string, r any) {
	fmt.Fprintf(os.Stderr, "PANIC in %s: %v\n%s\n", where, r, debug.Stack())
}

func (a *App) shutdownTunnel() {
	a.mu.Lock()
	a.wantConnected = false
	old := a.nativeSession
	a.nativeSession = nil
	a.tunnelConnectedAt = ""
	a.mu.Unlock()
	if old != nil {
		old.Stop()
	} else {
		_ = recoverStartupRoutes()
	}
}

func (a *App) nativeStatus() (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nativeSession == nil {
		return false, errors.New("tunnel is not connected")
	}
	return true, nil
}

func decodeTunnelLine(line string) (ptunnel.Profile, error) {
	if !strings.HasPrefix(line, profilePrefix) {
		return ptunnel.Profile{}, errors.New("not a profile record")
	}
	return ptunnel.DecodeProfile(strings.TrimPrefix(line, profilePrefix))
}

// Avoid ever emitting profiles or secret tokens in the installer log.
func redactProfileLog(line string) string {
	if strings.HasPrefix(line, profilePrefix) {
		return "Конфигурация туннеля получена и сохранена."
	}
	if strings.Contains(line, "PORTLINE_TUNNEL_PROFILE=") {
		return "[секрет конфигурации скрыт]"
	}
	return line
}

func explainTunnelError(profile ptunnel.Profile, err error) string {
	base := fmt.Sprintf("Не удалось подключиться к %s:%d", profile.Host, profile.Port)
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "server identity changed"):
		return base + ": серверный ключ изменился. Скорее всего, это другой сервер или Portline уже переустанавливали на VPS. Переустанови Portline и сохрани новый профиль подключения."
	case strings.Contains(lower, "сервер не подтвердил ключ подключения") || strings.Contains(lower, "did not confirm"):
		return base + ": сервер не принял сохранённый ключ доступа. Возможно, на компьютере остался старый локальный профиль или на VPS стоит другая конфигурация Portline. Переустанови Portline на нужном порту."
	case strings.Contains(lower, "tls-рукопожатие") && (strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") || strings.Contains(lower, "wsarecv")):
		return base + ": TCP удалось открыть, но TLS-рукопожатие Portline не завершилось. Порт может быть открыт, но на нём работает другая служба, неверная версия Gateway или сетевой фильтр прерывает TLS. Нажми «Проверить протокол», затем проверь журнал Gateway на VPS."
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") || strings.Contains(lower, "wsarecv") || strings.Contains(lower, "failed to respond"):
		return base + ": сервер не ответил вовремя. Возможные причины: порт закрыт в firewall или панели VPS, служба Portline не запущена, на этом порту отвечает другая служба, либо у тебя сохранён профиль от старого порта. Проверь порт, открой его на VPS и при необходимости освободи или выбери другой."
	case strings.Contains(lower, "actively refused") || strings.Contains(lower, "connection refused"):
		return base + ": соединение отклонено. Обычно это значит, что служба на этом порту не слушает подключения или порт закрыт. Проверь, что Portline gateway запущен и порт открыт."
	case strings.Contains(lower, "certificate") || strings.Contains(lower, "tls"):
		return base + ": TLS-проверка не прошла. Возможно, подключение идёт не к службе Portline или на порту отвечает другая служба."
	default:
		return base + ": " + msg
	}
}
