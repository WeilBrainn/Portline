package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const githubRepo = "WeilBrainn/Portline"

type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	HasUpdate      bool   `json:"hasUpdate"`
	ReleaseURL     string `json:"releaseUrl,omitempty"`
	DownloadURL    string `json:"downloadUrl,omitempty"`
	CanSelfUpdate  bool   `json:"canSelfUpdate"`
	Error          string `json:"error,omitempty"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Draft   bool          `json:"draft"`
	Assets  []githubAsset `json:"assets"`
}

func parseSemverParts(v string) [3]int {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}

// isNewerVersion returns true when latest is strictly newer than current,
// or when numeric versions match and current is a prerelease while latest is stable.
func isNewerVersion(current, latest string) bool {
	c := parseSemverParts(current)
	l := parseSemverParts(latest)
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return strings.Contains(current, "-") && !strings.Contains(latest, "-")
}

func checkGitHubUpdate(ctx context.Context) UpdateInfo {
	info := UpdateInfo{CurrentVersion: version}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Portline/"+version)

	resp, err := (&http.Client{Timeout: 7 * time.Second}).Do(req)
	if err != nil {
		info.Error = "Не удалось связаться с GitHub."
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		info.LatestVersion = version
		info.ReleaseURL = fmt.Sprintf("https://github.com/%s/releases", githubRepo)
		return info
	}
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("GitHub API вернул HTTP %d", resp.StatusCode)
		return info
	}

	var rel githubRelease
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 256*1024)).Decode(&rel); err != nil {
		info.Error = "Не удалось разобрать ответ GitHub."
		return info
	}
	if rel.TagName == "" {
		info.LatestVersion = version
		return info
	}

	latest := strings.TrimPrefix(rel.TagName, "v")
	info.LatestVersion = latest
	info.HasUpdate = isNewerVersion(version, latest)
	if strings.HasPrefix(rel.HTMLURL, "https://github.com/"+githubRepo) {
		info.ReleaseURL = rel.HTMLURL
	} else {
		info.ReleaseURL = fmt.Sprintf("https://github.com/%s/releases", githubRepo)
	}
	for _, asset := range rel.Assets {
		if asset.Name == "Portline.exe" && isAllowedDownloadURL(asset.BrowserDownloadURL) {
			info.DownloadURL = asset.BrowserDownloadURL
			info.CanSelfUpdate = runtime.GOOS == "windows"
			break
		}
	}
	return info
}

func isAllowedDownloadURL(u string) bool {
	return strings.HasPrefix(u, "https://github.com/"+githubRepo+"/") ||
		strings.HasPrefix(u, "https://objects.githubusercontent.com/")
}

func (a *App) installSelfUpdate(ctx context.Context) error {
	if runtime.GOOS != "windows" {
		return errors.New("автообновление поддерживается только на Windows")
	}
	info := checkGitHubUpdate(ctx)
	if info.Error != "" {
		return errors.New(info.Error)
	}
	if !info.HasUpdate || info.DownloadURL == "" {
		return errors.New("обновление недоступно или файл Portline.exe отсутствует в релизе")
	}
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dlCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, info.DownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Portline/"+version)
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("ошибка скачивания обновления: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул HTTP %d при скачивании", resp.StatusCode)
	}

	tmpPath := exePath + ".new"
	_ = os.Remove(tmpPath)
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("не удалось создать временный файл обновления: %w", err)
	}
	n, copyErr := io.Copy(out, io.LimitReader(resp.Body, 80<<20))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || n < 1024*1024 || n >= 80<<20 {
		_ = os.Remove(tmpPath)
		return errors.New("скачанный файл обновления повреждён")
	}
	var hdr [2]byte
	if f, err := os.Open(tmpPath); err == nil {
		_, _ = f.Read(hdr[:])
		_ = f.Close()
	}
	if hdr[0] != 'M' || hdr[1] != 'Z' {
		_ = os.Remove(tmpPath)
		return errors.New("скачанный файл не является корректным Windows EXE")
	}

	a.shutdownTunnel()

	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("не удалось заменить текущий EXE: %w", err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		_ = os.Rename(oldPath, exePath)
		_ = os.Remove(tmpPath)
		return fmt.Errorf("не удалось активировать новый EXE: %w", err)
	}

	if err := exec.Command(exePath).Start(); err != nil {
		return fmt.Errorf("обновление установлено, но не удалось перезапустить: %w", err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		a.requestQuit()
	}()
	return nil
}
