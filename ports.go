package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func portIdentity(r InstallRequest) string {
	return fmt.Sprintf("%s:%d/%s:%d", r.Host, r.SSHPort, r.Protocol, r.Port)
}

func applyPortReport(p *PortTask, report string) error {
	parts := strings.Split(strings.TrimPrefix(report, "PORTLINE_PORT|"), "|")
	if len(parts) != 7 {
		return errors.New("неверный формат")
	}
	state, protocol := parts[0], parts[1]
	if state != "free" && state != "busy" && state != "stopped" {
		return errors.New("неверный статус")
	}
	if protocol != "tcp" && protocol != "udp" {
		return errors.New("неверный протокол")
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil || port < 1 || port > 65535 {
		return errors.New("неверный порт")
	}
	pid := 0
	if parts[5] != "-" {
		pid, err = strconv.Atoi(parts[5])
		if err != nil || pid < 0 {
			return errors.New("неверный PID")
		}
	}
	unit, proc := parts[3], parts[4]
	if unit == "-" {
		unit = ""
	}
	if proc == "-" {
		proc = ""
	}
	if len(unit) > 100 || len(proc) > 100 {
		return errors.New("неверное имя процесса")
	}
	p.State, p.Protocol, p.Port, p.Service, p.Process, p.PID = state, protocol, port, unit, proc, pid
	p.CanStop = state == "busy" && parts[6] == "1" && strings.HasSuffix(unit, ".service")
	switch state {
	case "free":
		p.Message = fmt.Sprintf("%s %d свободен на сервере.", strings.ToUpper(protocol), port)
	case "busy":
		p.Message = fmt.Sprintf("%s %d занят службой %s.", strings.ToUpper(protocol), port, proc)
	case "stopped":
		p.Message = fmt.Sprintf("Служба %s остановлена. %s %d освобождён.", unit, strings.ToUpper(protocol), port)
	}
	return nil
}

func parsePortSuggestions(raw string) []int {
	result := []int{}
	seen := map[int]bool{}
	for _, value := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1024 || port > 65535 || seen[port] {
			continue
		}
		result = append(result, port)
		seen[port] = true
		if len(result) == 3 {
			break
		}
	}
	return result
}

func (a *App) runPortTask(r InstallRequest, action, expectedService string) {
	defer func() { a.mu.Lock(); a.portBusy = false; a.mu.Unlock() }()
	script, err := assets.ReadFile("scripts/portctl.sh")
	if err == nil {
		proto := "tcp"
		if r.Protocol == "hy2" {
			proto = "udp"
		}
		env := fmt.Sprintf("export NP_PORT=%s NP_CTL_PROTO=%s NP_CTL_ACTION=%s NP_EXPECT_UNIT=%s NP_SSH_PORT=%s\n",
			shellQuote(strconv.Itoa(r.Port)), shellQuote(proto), shellQuote(action),
			shellQuote(expectedService), shellQuote(strconv.Itoa(r.SSHPort)))
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
		defer cancel()
		err = a.runTransport(ctx, r, env+string(script))
	}
	a.modify(func(s *AppStatus) {
		if err != nil {
			s.PortTask.State = "error"
			s.PortTask.Message = fmt.Sprintf("Не удалось изменить или проверить порт: %v", err)
		} else if s.PortTask.State == "running" {
			s.PortTask.State = "error"
			s.PortTask.Message = "Сервер не вернул результат проверки порта."
		}
	})
}
