package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const gatewayTargetVersion = "1.4.0"

type GatewayInspection struct {
	State         string `json:"state"`
	Activity      string `json:"activity"`
	Port          string `json:"port"`
	Version       string `json:"version"`
	ConfigVersion string `json:"configVersion"`
	Host          string `json:"host"`
	Compatible    bool   `json:"compatible"`
	NeedsUpdate   bool   `json:"needsUpdate"`
	Message       string `json:"message"`
}

var gwVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,40}$`)

func parseGatewayInspection(line string) (GatewayInspection, error) {
	parts := strings.Split(strings.TrimSpace(line), "|")
	if len(parts) != 7 || parts[0] != "PORTLINE_GATEWAY" {
		return GatewayInspection{}, errors.New("неверный формат отчёта Gateway")
	}
	if parts[1] == "missing" && parts[2] == "-" && parts[3] == "-" && parts[4] == "-" && parts[5] == "-" && parts[6] == "-" {
		return GatewayInspection{State: "missing", Port: "-", Version: "-", Message: "Portline Gateway не найден."}, nil
	}
	if parts[1] != "installed" || (parts[2] != "active" && parts[2] != "inactive") {
		return GatewayInspection{}, errors.New("неверное состояние Gateway")
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n < 1 || n > 65535 {
		return GatewayInspection{}, errors.New("неверный порт Gateway")
	}
	if parts[4] != "legacy" && !gwVersionRE.MatchString(parts[4]) {
		return GatewayInspection{}, errors.New("неверная версия Gateway")
	}
	if parts[5] != "1" && parts[5] != "2" && parts[5] != "unknown" {
		return GatewayInspection{}, errors.New("неизвестный формат конфигурации")
	}
	if !hostRe.MatchString(parts[6]) || len(parts[6]) > 253 || strings.Contains(parts[6], "..") {
		return GatewayInspection{}, errors.New("неверный адрес Gateway")
	}
	report := GatewayInspection{State: parts[1], Activity: parts[2], Port: parts[3], Version: parts[4], ConfigVersion: parts[5], Host: parts[6], Compatible: parts[5] == "1"}
	report.NeedsUpdate = report.Compatible && report.Version != gatewayTargetVersion
	switch {
	case !report.Compatible:
		report.Message = "Версия конфигурации не поддерживается. Автообновление заблокировано; потребуется ручная миграция после резервного копирования."
	case report.NeedsUpdate:
		report.Message = fmt.Sprintf("Gateway найден: %s → %s (схема конфига v%s без изменений). Перед заменой будет сохранена резервная копия бинарника, unit-файла и конфигурации.", report.Version, gatewayTargetVersion, report.ConfigVersion)
	case report.Activity != "active":
		report.Message = "Gateway найден, но служба остановлена. Проверь журнал systemd."
	default:
		report.Message = "Gateway установлен и совместим. Можно использовать существующий сервер без переустановки."
	}
	return report, nil
}

func classifySSHFailure(err error, logs []string) string {
	s := strings.ToLower(strings.Join(logs, "\n"))
	if err != nil {
		s += "\n" + strings.ToLower(err.Error())
	}
	switch {
	case strings.Contains(s, "permission denied (publickey") || strings.Contains(s, "permission denied, please try again") || strings.Contains(s, "authentication failed"):
		return "Ошибка SSH-аутентификации. Проверь пользователя и пароль/ключ. Если PuTTY подключается, сравни пользователя, порт и способ входа."
	case strings.Contains(s, "sudo:") || strings.Contains(s, "must be root") || strings.Contains(s, "требуются права root"):
		return "SSH подключился, но команда требует root или sudo без запроса пароля. Используй root либо настрой права sudo на VPS."
	case strings.Contains(s, "gateway already installed"):
		return "Portline Gateway уже установлен на VPS. Вместо повторной установки нажми «Проверить Gateway», затем «Использовать существующий сервер» или обнови его с резервной копией."
	case strings.Contains(s, "gateway already configured") || strings.Contains(s, "existing server config invalid"):
		return "Конфигурация Gateway отличается от выбранного адреса или порта. Проверь установленную службу и выбери «Использовать существующий»; автоматическая перезапись запрещена."
	case strings.Contains(s, "systemctl") || strings.Contains(s, "journalctl") || strings.Contains(s, "failed to start") || strings.Contains(s, "служба portline не запустилась"):
		return "SSH подключился, но серверная служба не запустилась. Проверь порт, статус systemd и журнал Gateway."
	case strings.Contains(s, "connection refused") || strings.Contains(s, "connection timed out") || strings.Contains(s, "network is unreachable"):
		return "Сетевая ошибка SSH: сервер или SSH-порт недоступен. Проверь адрес, порт и firewall VPS."
	case strings.Contains(s, "address already in use") || strings.Contains(s, "already in use") || strings.Contains(s, "порт уже занят"):
		return "Установщик не смог занять VPN-порт: там уже слушает служба. Проверь Gateway прежде чем выбирать другой порт или останавливать процессы."
	case strings.Contains(s, "bash: command not found") || strings.Contains(s, "bash: not found"):
		return "SSH работает, но на сервере не найден Bash. Установи пакет bash на VPS."
	default:
		if err == nil {
			return "Операция не завершена: проверь журнал SSH и установщика."
		}
		return "SSH-команда завершилась с ошибкой. Подключение SSH и установка — разные этапы. Проверь последние строки журнала; исходная ошибка: " + err.Error()
	}
}

func gatewayScript(action string, r InstallRequest) (string, error) {
	data, err := assets.ReadFile("scripts/gateway.sh")
	if err != nil {
		return "", err
	}
	env := fmt.Sprintf("export NP_GW_ACTION=%s NP_ADDR=%s NP_PORT=%s\n", shellQuote(action), shellQuote(r.Host), shellQuote(strconv.Itoa(r.Port)))
	text := string(data)
	if action == "update" {
		binary, e := assets.ReadFile("bin/portline-gateway-linux-amd64")
		if e != nil {
			return "", e
		}
		digest := sha256.Sum256(binary)
		encoded := base64.StdEncoding.EncodeToString(binary)
		var body strings.Builder
		for i := 0; i < len(encoded); i += 76 {
			end := i + 76
			if end > len(encoded) {
				end = len(encoded)
			}
			body.WriteString(encoded[i:end])
			body.WriteByte('\n')
		}
		env += fmt.Sprintf("export NP_BIN_SHA=%s\n", shellQuote(hex.EncodeToString(digest[:])))
		text = strings.Replace(text, "__BINARY_BODY__", strings.TrimSuffix(body.String(), "\n"), 1)
	} else {
		text = strings.ReplaceAll(text, "__BINARY_BODY__", "")
	}
	return env + text, nil
}

func (a *App) runGatewayAction(r InstallRequest, action string) {
	defer func() { a.mu.Lock(); a.gatewayBusy = false; a.mu.Unlock() }()
	script, err := gatewayScript(action, r)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err = a.runTransport(ctx, r, script)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.status.GatewayError = classifySSHFailure(err, a.status.Logs)
		a.status.GatewayAction = "error"
		return
	}
	if action == "inspect" && a.status.Gateway.State == "" {
		a.status.GatewayAction = "error"
		a.status.GatewayError = "Сервер не вернул данные Gateway."
		return
	}
	if action == "use" && !a.installProfileSeen {
		a.status.GatewayAction = "error"
		a.status.GatewayError = "Сервер не вернул совместимый профиль; старый локальный профиль не используется."
		return
	}
	a.status.GatewayAction = "success"
	if action == "use" {
		a.status.State = "success"
		a.status.Protocol = "portline"
		a.status.Host = a.tunnelProfile.Host
		a.status.HasNativeProfile = true
	}
}
