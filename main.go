package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
)

//go:embed ui/* scripts/* bin/*
var assets embed.FS

const version = "1.4.5"

func openUI(url string) {
	if os.Getenv("PORTLINE_NO_BROWSER") == "1" {
		return
	}
	if runtime.GOOS == "windows" {
		paths := []string{
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		}
		if p, err := exec.LookPath("msedge.exe"); err == nil {
			paths = append([]string{p}, paths...)
		}
		for _, p := range paths {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				if err := exec.Command(p, "--app="+url, "--window-size=1290,840", "--no-first-run").Start(); err == nil {
					return
				}
			}
		}
		_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
		return
	}
	if runtime.GOOS == "darwin" {
		_ = exec.Command("open", url).Start()
		return
	}
	_ = exec.Command("xdg-open", url).Start()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--ssh-askpass" {
		fmt.Println(os.Getenv("PORTLINE_ASKPASS"))
		return
	}
	// OpenSSH launches SSH_ASKPASS without arguments except the prompt text.
	if v := os.Getenv("PORTLINE_ASKPASS"); v != "" {
		fmt.Println(v)
		return
	}
	release, err := acquireAppInstance()
	if err != nil {
		if errors.Is(err, errExistingInstanceNotified) {
			return
		}
		notifyStartupFailure(err.Error())
		return
	}
	defer release()
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
	if dir, err := appDir(); err == nil {
		if f, err := os.OpenFile(filepath.Join(dir, "portline-runtime.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
			redirectStderr(f)
			log.SetOutput(f)
			defer f.Close()
		}
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC: %v\n%s", r, debug.Stack())
		}
	}()
	app := &App{token: randomHex(24), lastAccess: time.Now(), quitCh: make(chan struct{}), status: AppStatus{State: "idle", Phase: "Ожидание", Progress: 0, Logs: []string{}, HAPP: HAPPTask{State: "idle"}}}
	if servers, err := loadSavedServers(); err == nil {
		app.savedServers = servers
	}
	if profile, ok := restoreTunnelProfile(); ok {
		app.status.State = "success"
		app.status.Phase = "Сохранённый профиль"
		app.status.Progress = 100
		app.status.Protocol = "portline"
		app.status.Host = profile.Host
		app.status.HasNativeProfile = true
		app.status.NativeProfileHost = profile.Host
		app.status.NativeProfilePort = profile.Port
		app.tunnelProfile = profile
		app.status.Tunnel = TunnelTask{State: "idle", Message: "Сохранённый профиль готов к подключению."}
	}
	if err := recoverStartupRoutes(); err != nil {
		app.status.Tunnel = TunnelTask{State: "error", Message: "Не удалось восстановить сеть после предыдущего подключения. Запусти Portline от имени администратора: " + err.Error()}
	} else if app.status.HasNativeProfile {
		app.status.Tunnel = TunnelTask{State: "idle", Message: "Сеть проверена. Профиль готов к подключению."}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(app.serveHTTP), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	fmt.Printf("Portline %s · %s\n", version, url)
	stopTray := startTray(url, app, app.requestQuit)
	defer stopTray()
	openUI(url)
	<-app.quitCh
	stopTray()
	app.shutdownTunnel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = server.Shutdown(ctx)
	cancel()
}
