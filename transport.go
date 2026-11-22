package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Portable Plink is fetched only when OpenSSH is missing and can be used with
// a password or a PuTTY key. Verify its digest before running it.
const (
	plinkURL    = "https://the.earth.li/~sgtatham/putty/0.85/w64/plink.exe"
	plinkSHA256 = "969f36879d5716aa1a9811f43a6a6510e8f08372dbeb9695b810b9c776f39c75"
)

var fingerprintRE = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}=?`)

func findOpenSSH() (string, error) {
	if bin, err := exec.LookPath("ssh.exe"); err == nil {
		return bin, nil
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("SystemRoot")
		if base == "" {
			base = `C:\Windows`
		}
		p := filepath.Join(base, "System32", "OpenSSH", "ssh.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return exec.LookPath("ssh")
}

func appDir() (string, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(config, "Portline")
	return dir, os.MkdirAll(dir, 0700)
}

func (a *App) runTransport(ctx context.Context, r InstallRequest, script string) error {
	if ssh, err := findOpenSSH(); err == nil {
		a.appendLog("OpenSSH найден. Настраиваю защищённое соединение…")
		return a.runOpenSSH(ctx, ssh, r, script)
	}
	if runtime.GOOS != "windows" {
		return errors.New("На этой системе не найден OpenSSH. Установи пакет openssh-client.")
	}
	// Portable Plink handles passwords and PuTTY .ppk keys. OpenSSH-format
	// keys need native OpenSSH, so skip incompatible transports here.
	canUsePortable := r.Auth == "password" || strings.EqualFold(filepath.Ext(r.KeyFile), ".ppk")
	var downloadErr error
	if canUsePortable {
		a.appendLog("SSH-клиент не найден. Получаю проверенный компонент в фоне…")
		a.modify(func(s *AppStatus) { s.Phase = "Подготовка SSH-подключения"; s.Progress = 8 })
		var plink string
		plink, downloadErr = ensurePortablePlink(ctx)
		if downloadErr == nil {
			a.appendLog("SSH-компонент скачан и проверен по SHA-256. Подключаюсь к серверу…")
			return a.runPlink(ctx, plink, r, script)
		}
	} else {
		a.appendLog("Для выбранного ключа требуется OpenSSH. Подготавливаю компонент Windows…")
	}

	a.appendLog("Переносной SSH-клиент недоступен. Пробую установить компонент Windows…")
	a.modify(func(s *AppStatus) { s.Phase = "Установка системного SSH"; s.Progress = 10 })
	// An operating-system UAC consent prompt can be displayed here. It is not
	// a terminal window and must not be bypassed programmatically.
	if err := autoInstallOpenSSH(ctx); err != nil {
		return fmt.Errorf("Автоматическая подготовка SSH не удалась (переносной и Windows OpenSSH). Проверь доступ к интернету и разрешения Windows: %w", err)
	}
	ssh, err := findOpenSSH()
	if err != nil {
		return errors.New("Windows сообщила об установке OpenSSH, но клиент не найден")
	}
	a.appendLog("Системный SSH установлен. Подключаюсь к серверу…")
	return a.runOpenSSH(ctx, ssh, r, script)
}

func autoInstallOpenSSH(ctx context.Context) error {
	if runtime.GOOS != "windows" {
		return errors.New("Windows only")
	}
	// This invokes the Microsoft optional feature installer. UAC is OS-managed.
	installScript := `$ErrorActionPreference='Stop'; Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0' | Out-Null; if (-not (Test-Path "$env:WINDIR\System32\OpenSSH\ssh.exe")) { exit 13 }`
	utf16words := utf16.Encode([]rune(installScript))
	raw := make([]byte, 2*len(utf16words))
	for i, w := range utf16words {
		raw[i*2] = byte(w)
		raw[i*2+1] = byte(w >> 8)
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	// The current user may be non-admin. Start-Process invokes UAC if required.
	ps := `$p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile -NonInteractive -EncodedCommand ` + enc + `'; exit $p.ExitCode`
	installCtx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	cmd := backgroundCommand(installCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = out // Do not leak detailed PowerShell messages to the UI; use portable fallback.
		return err
	}
	_, err := findOpenSSH()
	return err
}

func validPlinkDigest(data []byte) bool {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]) == plinkSHA256
}

func ensurePortablePlink(ctx context.Context) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("Plink доступен только в Windows-сборке")
	}
	dir, err := appDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "tools")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "plink-0.85.exe")
	if b, err := os.ReadFile(path); err == nil && validPlinkDigest(b) {
		return path, nil
	}
	// PowerShell runs without a console. If execution policy, Windows settings,
	// or a missing PowerShell executable prevents it, a direct Go HTTPS
	// download is a safe secondary path. The same pinned hash is mandatory.
	temp := path + ".partial"
	defer os.Remove(temp)
	if err := silentPowerShellDownload(ctx, plinkURL, temp); err != nil {
		if err := directDownload(ctx, plinkURL, temp); err != nil {
			return "", fmt.Errorf("не удалось получить SSH-клиент по HTTPS: %w", err)
		}
	}
	b, err := os.ReadFile(temp)
	if err != nil {
		return "", err
	}
	if !validPlinkDigest(b) {
		return "", errors.New("контрольная сумма загруженного SSH-клиента не совпала; запуск отменён")
	}
	if err := os.Rename(temp, path); err != nil {
		return "", err
	}
	return path, nil
}

func (a *App) runOpenSSH(ctx context.Context, sshbin string, r InstallRequest, script string) error {
	dir, err := appDir()
	if err != nil {
		return err
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	args := []string{"-T", "-p", fmt.Sprint(r.SSHPort), "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
		"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "NumberOfPasswordPrompts=1", "-o", "BatchMode=no"}
	if r.Auth == "key" {
		args = append(args, "-i", r.KeyFile, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey")
	} else {
		args = append(args, "-o", "PreferredAuthentications=password,keyboard-interactive")
	}
	args = append(args, r.Username+"@"+r.Host)
	if r.Username == "root" {
		args = append(args, "bash -s")
	} else {
		args = append(args, "sudo -n bash -s")
	}
	cmd := backgroundCommand(ctx, sshbin, args...)
	cmd.Stdin = strings.NewReader(script)
	if r.Auth == "password" {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		// OpenSSH invokes this executable as SSH_ASKPASS, avoiding argv disclosure.
		cmd.Env = append(os.Environ(), "SSH_ASKPASS="+self, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=portline:0", "PORTLINE_ASKPASS="+r.Password)
	}
	if err := a.streamCommand(cmd); err != nil {
		return fmt.Errorf("Не удалось подключиться по SSH или завершить настройку: %w. Проверь пароль, доступность SSH-порта и журнал", err)
	}
	return nil
}

func fingerprintFromPlink(output string) string {
	return fingerprintRE.FindString(output)
}

func hostID(r InstallRequest) string { return fmt.Sprintf("%s:%d", r.Host, r.SSHPort) }

func readPinnedHosts(path string) (map[string]string, error) {
	hosts := map[string]string{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return hosts, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &hosts); err != nil {
		return nil, fmt.Errorf("повреждён файл сохранённых SSH-отпечатков: %w", err)
	}
	return hosts, nil
}

func recordPinnedHost(path, id, fp string) error {
	if !fingerprintRE.MatchString(fp) {
		return errors.New("некорректный отпечаток SSH-хоста")
	}
	hosts, err := readPinnedHosts(path)
	if err != nil {
		return err
	}
	if prev, ok := hosts[id]; ok && prev != fp {
		return errors.New("отпечаток SSH-ключа изменился; подключение остановлено")
	}
	hosts[id] = fp
	b, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (a *App) runPlink(ctx context.Context, plink string, r InstallRequest, script string) error {
	dir, err := appDir()
	if err != nil {
		return err
	}
	known := filepath.Join(dir, "pinned-hosts.json")
	hosts, err := readPinnedHosts(known)
	if err != nil {
		return err
	}
	fp := hosts[hostID(r)]
	if fp == "" {
		// Initial connection discovers the fingerprint but does not authenticate.
		probeCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		args := []string{"-v", "-batch", "-ssh", "-P", fmt.Sprint(r.SSHPort), "-l", r.Username, r.Host, "exit"}
		output, _ := backgroundCommand(probeCtx, plink, args...).CombinedOutput()
		fp = fingerprintFromPlink(string(output))
		if fp == "" {
			return errors.New("не удалось получить SSH-отпечаток сервера. Проверь IP, порт SSH и сетевой доступ")
		}
		if err := recordPinnedHost(known, hostID(r), fp); err != nil {
			return err
		}
		a.appendLog("SSH-отпечаток сервера сохранён при первом подключении. При изменении ключа соединение будет остановлено.")
	}
	args := []string{"-batch", "-ssh", "-P", fmt.Sprint(r.SSHPort), "-l", r.Username, "-noagent", "-hostkey", fp}
	var passwordFile string
	if r.Auth == "password" {
		// PuTTY supports -pwfile; avoid including passwords in process arguments.
		f, err := os.CreateTemp(dir, "ssh-password-*.txt")
		if err != nil {
			return err
		}
		passwordFile = f.Name()
		defer os.Remove(passwordFile)
		if err := f.Chmod(0600); err != nil {
			f.Close()
			return err
		}
		if _, err := f.WriteString(r.Password + "\n"); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		args = append(args, "-pwfile", passwordFile)
	} else {
		if !strings.EqualFold(filepath.Ext(r.KeyFile), ".ppk") {
			return errors.New("Резервный SSH-клиент PuTTY принимает ключи .ppk. Выбери вход по паролю либо установи OpenSSH для использования ключей OpenSSH")
		}
		args = append(args, "-i", r.KeyFile)
	}
	args = append(args, r.Host)
	if r.Username == "root" {
		args = append(args, "bash -s")
	} else {
		args = append(args, "sudo -n bash -s")
	}
	cmd := backgroundCommand(ctx, plink, args...)
	cmd.Stdin = strings.NewReader(script)
	if err := a.streamCommand(cmd); err != nil {
		return fmt.Errorf("Не удалось завершить SSH-установку через резервный клиент: %w. Проверь данные SSH и журнал", err)
	}
	return nil
}

func (a *App) streamCommand(cmd *exec.Cmd) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	scan := func(reader io.Reader) {
		defer wg.Done()
		buf := make([]byte, 16*1024)
		var pending bytes.Buffer
		for {
			n, e := reader.Read(buf)
			if n > 0 {
				pending.Write(buf[:n])
			}
			for {
				b := pending.Bytes()
				idx := bytes.IndexByte(b, '\n')
				if idx < 0 {
					break
				}
				a.appendLog(string(b[:idx]))
				pending.Next(idx + 1)
			}
			if pending.Len() > 8192 {
				a.appendLog(pending.String())
				pending.Reset()
			}
			if e != nil {
				break
			}
		}
		if pending.Len() > 0 {
			a.appendLog(pending.String())
		}
	}
	go scan(stdout)
	go scan(stderr)
	err = cmd.Wait()
	wg.Wait()
	return err
}

// silentPowerShellDownload does not print progress to the desktop. The HTTP
// client fallback below also avoids shell windows entirely.
func silentPowerShellDownload(ctx context.Context, url, destination string) error {
	if runtime.GOOS != "windows" {
		return errors.New("Windows only")
	}
	c, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	script := `$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; Invoke-WebRequest -UseBasicParsing -Uri $env:PORTLINE_DL_URL -OutFile $env:PORTLINE_DL_FILE`
	cmd := backgroundCommand(c, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "PORTLINE_DL_URL="+url, "PORTLINE_DL_FILE="+destination)
	if err := cmd.Run(); err != nil {
		return err
	}
	fi, err := os.Stat(destination)
	if err != nil {
		return err
	}
	if fi.Size() == 0 || fi.Size() > 8<<20 {
		return errors.New("некорректный размер скачанного файла")
	}
	return nil
}

func directDownload(ctx context.Context, url, destination string) error {
	_ = os.Remove(destination)
	c := http.Client{Timeout: 45 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := c.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, io.LimitReader(response.Body, (8<<20)+1))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	fi, err := os.Stat(destination)
	if err != nil {
		return err
	}
	if fi.Size() == 0 || fi.Size() > 8<<20 {
		return errors.New("некорректный размер скачанного файла")
	}
	return nil
}
