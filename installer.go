package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (a *App) install(r InstallRequest) {
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()
	a.mu.Lock()
	a.expectFreshProfile = r.Protocol == "portline"
	a.installProfileSeen = false
	if a.expectFreshProfile {
		a.status.NeedsFreshProfile = true
	}
	a.mu.Unlock()
	name := "scripts/vless.sh"
	if r.Protocol == "hy2" {
		name = "scripts/hy2.sh"
	} else if r.Protocol == "portline" {
		name = "scripts/portline.sh"
	}
	script, err := assets.ReadFile(name)
	if err != nil {
		a.fail(err)
		return
	}
	scriptData := fmt.Sprintf("export NP_ADDR=%s NP_PORT=%s NP_SNI=%s\n", shellQuote(r.Host), shellQuote(strconv.Itoa(r.Port)), shellQuote(r.SNI)) + string(script)
	if r.Protocol == "portline" {
		gateway, readErr := assets.ReadFile("bin/portline-gateway-linux-amd64")
		if readErr != nil {
			a.fail(readErr)
			return
		}
		digest := sha256.Sum256(gateway)
		encoded := base64.StdEncoding.EncodeToString(gateway)
		var lines strings.Builder
		for i := 0; i < len(encoded); i += 76 {
			end := i + 76
			if end > len(encoded) {
				end = len(encoded)
			}
			lines.WriteString(encoded[i:end])
			lines.WriteByte('\n')
		}
		scriptData = fmt.Sprintf("export NP_ADDR=%s NP_PORT=%s NP_BIN_SHA=%s\n", shellQuote(r.Host), shellQuote(strconv.Itoa(r.Port)), shellQuote(hex.EncodeToString(digest[:]))) + strings.Replace(string(script), "__BINARY_BODY__", strings.TrimSuffix(lines.String(), "\n"), 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	if err := a.runTransport(ctx, r, scriptData); err != nil {
		if ctx.Err() != nil {
			a.fail(errors.New("Время настройки истекло. Проверь состояние VPS, затем попробуй повторить установку."))
		} else {
			a.fail(err)
		}
		return
	}
	a.mu.Lock()
	expectFreshProfile := a.expectFreshProfile
	profileSeen := a.installProfileSeen
	a.expectFreshProfile = false
	a.installProfileSeen = false
	if r.Protocol == "portline" && expectFreshProfile && !profileSeen {
		a.status.State = "error"
		a.status.Error = "Portline gateway не вернул новый профиль подключения. Чтобы не использовать старый локальный профиль, подключение заблокировано. Проверь журнал установки, затем повтори настройку на нужном порту."
		a.status.NeedsFreshProfile = true
	} else if a.status.Link == "" && !a.status.HasNativeProfile {
		a.status.State = "error"
		a.status.Error = "Служба запустилась, но ссылка на подключение не получена. Проверь журнал."
	} else {
		a.status.State = "success"
		a.status.Phase = "Сервер готов"
		a.status.Progress = 100
		a.status.NeedsFreshProfile = false
		a.status.Logs = append(a.status.Logs, "Установка завершена. Проверь сетевое подключение.")
	}
	a.mu.Unlock()
}

func (a *App) runHAPPInstall() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ok, message := installHAPP(ctx, func(phase string) {
		a.modify(func(s *AppStatus) {
			s.HAPP.Phase = phase
		})
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	a.happBusy = false
	a.status.HAPP.Message = message
	if ok {
		a.status.HAPP.State = "success"
	} else {
		a.status.HAPP.State = "error"
	}
}

func (a *App) fail(err error) {
	a.mu.Lock()
	a.expectFreshProfile = false
	a.installProfileSeen = false
	a.mu.Unlock()
	a.modify(func(s *AppStatus) {
		s.State = "error"
		s.Phase = "Ошибка установки"
		s.Error = classifySSHFailure(err, s.Logs)
		if s.PortConflict {
			s.Error = "Выбранный порт уже занят на VPS. Проверь его и выбери другой порт либо останови конфликтующую службу."
		} else if strings.Contains(strings.ToLower(err.Error()), "gateway already configured") {
			s.Error = "На VPS уже есть Portline gateway с другой привязкой порта или хоста. Чтобы не использовать старую конфигурацию, переустанови Portline на чистом сервере или вручную перенастрой существующий gateway."
		}
	})
}
