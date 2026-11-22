package main

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// HAPP's installer is invoked only after an explicit click. WinGet's silent
// mode is requested and the WinGet process runs without a visible console.
// Installer-controlled UAC prompts are deliberately not bypassed.
func installHAPP(ctx context.Context, progress func(string)) (bool, string) {
	if runtime.GOOS != "windows" {
		return false, "Установка HAPP из приложения доступна только на Windows."
	}
	progress("Проверка менеджера пакетов Windows")
	bin, err := exec.LookPath("winget.exe")
	if err != nil {
		bin, err = exec.LookPath("winget")
	}
	if err != nil {
		return false, "WinGet не найден. Установи HAPP с официальной страницы по ссылке ниже."
	}
	progress("HAPP устанавливается в фоновом режиме")
	installCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	args := []string{"install", "--id", "Happ.Happ", "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}
	cmd := backgroundCommand(installCtx, bin, args...)
	output, err := cmd.CombinedOutput()
	progress("Проверяю результат установки HAPP")
	if err != nil {
		if errors.Is(installCtx.Err(), context.DeadlineExceeded) {
			return false, "Установка HAPP превысила время ожидания. Проверь подключение к интернету и повтори попытку."
		}
		text := strings.ToLower(string(output))
		if strings.Contains(text, "already installed") || strings.Contains(text, "уже установлен") {
			return true, "HAPP уже установлен. Импортируй конфигурацию в приложении."
		}
		return false, "Автоматическая установка HAPP не удалась. Можно скачать его с официального сайта по ссылке ниже."
	}
	return true, "HAPP установлен. Импортируй профиль и включи режим TUN в настройках HAPP."
}
