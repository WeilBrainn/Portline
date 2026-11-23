package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"portline/internal/ptunnel"
)

// TunnelProbe checks a saved profile end-to-end without configuring Wintun,
// creating Windows routes or touching the remote server's configuration.
// A TCP-open port alone is NOT evidence that the Portline protocol works.
type TunnelProbe struct {
	State    string `json:"state"`
	Stage    string `json:"stage"`
	Endpoint string `json:"endpoint"`
	Message  string `json:"message"`
	Advice   string `json:"advice"`
}

func probePortline(parent context.Context, p ptunnel.Profile) TunnelProbe {
	result := TunnelProbe{State: "error", Stage: "profile", Endpoint: p.Endpoint()}
	if err := p.Validate(); err != nil {
		result.Message = "Сохранённый профиль Portline повреждён или несовместим."
		result.Advice = "Получите профиль заново через «Проверить Gateway» → «Использовать существующий»."
		return result
	}
	ctx, cancel := context.WithTimeout(parent, 9*time.Second)
	defer cancel()
	result.Stage = "tcp"
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 20 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", p.Endpoint())
	if err != nil {
		result.Message = "Не удалось открыть TCP-соединение: " + networkError(err)
		result.Advice = "Проверьте внешний IP, порт и правила доступа у VPS-провайдера."
		return result
	}
	defer raw.Close()
	tlsConfig, err := p.TLSConfig()
	if err != nil {
		result.Stage = "profile"
		result.Message = "Некорректные данные проверки TLS в профиле."
		return result
	}
	result.Stage = "tls"
	// Restrict each operation even if the parent context remains active.
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	conn := tls.Client(raw, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		if strings.Contains(err.Error(), "server identity changed") {
			result.Stage = "identity"
			result.Message = "TLS-сервер ответил, но его публичный ключ не совпал с сохранённым профилем."
			result.Advice = "Не отключайте проверку сертификата. Убедитесь, что это тот же VPS, и импортируйте актуальный профиль по SSH."
		} else {
			result.Message = "TCP-порт доступен, но TLS-рукопожатие Portline не завершилось: " + networkError(err)
			result.Advice = "Проверьте, что на этом порту слушает именно portline-gateway, а не HTTPS-сервер, прокси или другая служба. Проверьте systemctl status и journalctl."
		}
		return result
	}
	result.Stage = "auth"
	secret, _ := base64.RawURLEncoding.DecodeString(p.Token)
	if _, err := conn.Write(secret); err != nil {
		result.Message = "TLS работает, но токен не удалось отправить: " + networkError(err)
		result.Advice = "Проверьте подключение по SSH и журнал portline-gateway."
		return result
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		result.Message = "TLS работает, но Gateway не подтвердил доступ по сохранённому токену."
		result.Advice = "Проверьте, не занят ли Gateway другим подключением, и импортируйте актуальный профиль через SSH без переустановки."
		return result
	}
	result.State = "ok"
	result.Stage = "ready"
	result.Message = "TCP, TLS 1.3, закреплённый ключ сервера и токен Portline проверены."
	result.Advice = "Проверка подтверждает протокол, но не наличие системного туннеля, работу DNS или отсутствие IP-утечек."
	return result
}

func networkError(err error) string {
	if err == nil {
		return "нет ответа"
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "превышено время ожидания ответа"
	}
	return fmt.Sprintf("%v", err)
}
