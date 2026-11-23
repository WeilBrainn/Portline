package main

import (
	"fmt"
	"strconv"
	"strings"
)

// explainWindowsRouteConflict decodes a deliberately ASCII-only diagnostic
// emitted by the Windows preflight. Never render raw PowerShell stack traces:
// Windows PowerShell 5.1 uses a legacy console code page on some systems.
func explainWindowsRouteConflict(output []byte) (string, bool) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) != 5 || fields[0] != "PORTLINE_ROUTE_CONFLICT" {
			continue
		}
		prefix, indexText, owner := fields[1], fields[2], fields[4]
		if prefix != "0.0.0.0/1" && prefix != "128.0.0.0/1" && prefix != "::/1" && prefix != "8000::/1" {
			continue
		}
		index, err := strconv.Atoi(indexText)
		if err != nil || index < 1 || index > 65535 || (owner != "portline" && owner != "external") {
			continue
		}
		if owner == "portline" {
			return fmt.Sprintf("На сетевом адаптере Portline (интерфейс №%d) уже есть маршрут %s. Возможно, он остался после предыдущего подключения. Portline не будет заменять его без проверки. Перезапусти приложение от имени администратора для восстановления сети по журналу, затем повтори подключение. Если ошибка остаётся, проверь существующие маршруты — не удаляй их без подтверждения владельца.", index, prefix), true
		}
		return fmt.Sprintf("Найден маршрут %s через интерфейс №%d, не принадлежащий текущему адаптеру Portline. Это может быть маршрут другого VPN или вручную настроенной сети. Portline не удаляет чужие маршруты автоматически: сначала отключи другой VPN в его приложении, затем повтори подключение. Если другой VPN не запущен, проверь владельца маршрута командами Get-NetRoute и Get-NetAdapter.", prefix, index), true
	}
	return "", false
}
