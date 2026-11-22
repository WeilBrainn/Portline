package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

func (a *App) install(r InstallRequest) {
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()
	name := "scripts/vless.sh"
	if r.Protocol == "hy2" {
		name = "scripts/hy2.sh"
	}
	script, err := assets.ReadFile(name)
	if err != nil {
		a.fail(err)
		return
	}
	scriptData := fmt.Sprintf("export NP_ADDR=%s NP_PORT=%s NP_SNI=%s\n", shellQuote(r.Host), shellQuote(strconv.Itoa(r.Port)), shellQuote(r.SNI)) + string(script)
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
	if a.status.Link == "" {
		a.status.State = "error"
		a.status.Error = "Служба запустилась, но ссылка на подключение не получена. Проверь журнал."
	} else {
		a.status.State = "success"
		a.status.Phase = "Сервер готов"
		a.status.Progress = 100
		a.status.Logs = append(a.status.Logs, "Установка завершена. Проверь подключение через HAPP.")
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
	a.modify(func(s *AppStatus) {
		s.State = "error"
		s.Phase = "Ошибка установки"
		s.Error = err.Error()
		if s.PortConflict {
			s.Error = "Выбранный порт уже занят на VPS. Проверь его и выбери другой порт либо останови конфликтующую службу."
		}
	})
}
