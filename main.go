package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed ui/* scripts/*
var assets embed.FS

const version = "0.6.0"

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
	app := &App{token: randomHex(24), lastAccess: time.Now(), status: AppStatus{State: "idle", Phase: "Ожидание", Progress: 0, Logs: []string{}, HAPP: HAPPTask{State: "idle"}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(app.serveHTTP), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second}
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	fmt.Printf("Portline %s · %s\n", version, url)
	openUI(url)
	// Exit when the GUI has been inactive for an extended period, but not during remote work.
	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		app.mu.Lock()
		idle := time.Since(app.lastAccess) > 90*time.Second
		busy := app.busy || app.happBusy || app.portBusy
		app.mu.Unlock()
		if idle && !busy {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = server.Shutdown(ctx)
			cancel()
			return
		}
	}
}
