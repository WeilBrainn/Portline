package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type SavedServer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	SSHPort     int    `json:"sshPort"`
	Username    string `json:"username"`
	Auth        string `json:"auth"`
	KeyFile     string `json:"keyFile"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	SNI         string `json:"sni"`
	LastUsed    string `json:"lastUsed"`
	HasPassword bool   `json:"hasPassword,omitempty"`

	PasswordBlob string `json:"passwordBlob,omitempty"`
}

type saveProfileRequest struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	SSHPort      int    `json:"sshPort"`
	Username     string `json:"username"`
	Auth         string `json:"auth"`
	KeyFile      string `json:"keyFile"`
	Protocol     string `json:"protocol"`
	Port         int    `json:"port"`
	SNI          string `json:"sni"`
	Password     string `json:"password"`
	SavePassword bool   `json:"savePassword"`
}

type loadedProfile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	SSHPort     int    `json:"sshPort"`
	Username    string `json:"username"`
	Auth        string `json:"auth"`
	KeyFile     string `json:"keyFile"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	SNI         string `json:"sni"`
	Password    string `json:"password"`
	HasPassword bool   `json:"hasPassword"`
	LastUsed    string `json:"lastUsed"`
}

func (r saveProfileRequest) Validate() error {
	if !hostRe.MatchString(r.Host) || strings.Contains(r.Host, "..") || len(r.Host) > 253 {
		return errors.New("Укажи корректный IP-адрес или DNS-имя сервера.")
	}
	if r.SSHPort < 1 || r.SSHPort > 65535 || r.Port < 1 || r.Port > 65535 {
		return errors.New("Порты профиля должны быть в диапазоне 1–65535.")
	}
	if !userRe.MatchString(r.Username) {
		return errors.New("Некорректное SSH-имя пользователя.")
	}
	if r.Auth != "password" && r.Auth != "key" {
		return errors.New("Некорректный тип авторизации профиля.")
	}
	if r.Protocol != "vless" && r.Protocol != "hy2" && r.Protocol != "portline" {
		return errors.New("Некорректный протокол профиля.")
	}
	if r.Protocol == "vless" && r.SNI != "" && (!sniRe.MatchString(r.SNI) || strings.Contains(r.SNI, "..")) {
		return errors.New("Некорректный SNI в профиле.")
	}
	if r.SavePassword && r.Auth != "password" {
		return errors.New("Сохранение пароля доступно только для входа по SSH-паролю.")
	}
	if r.SavePassword && (len(r.Password) < 1 || len(r.Password) > 1024) {
		return errors.New("Чтобы сохранить профиль с паролем, сначала введи SSH-пароль.")
	}
	return nil
}

func (r saveProfileRequest) toSavedServer() (SavedServer, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = fmt.Sprintf("%s · %s:%d", protocolLabel(r.Protocol), r.Host, r.Port)
	}
	profile := SavedServer{
		ID:       strings.TrimSpace(r.ID),
		Name:     name,
		Host:     strings.TrimSpace(r.Host),
		SSHPort:  r.SSHPort,
		Username: strings.TrimSpace(r.Username),
		Auth:     r.Auth,
		KeyFile:  strings.TrimSpace(r.KeyFile),
		Protocol: r.Protocol,
		Port:     r.Port,
		SNI:      strings.TrimSpace(r.SNI),
		LastUsed: time.Now().Format(time.RFC3339),
	}
	if r.SavePassword {
		cipher, err := protectSecret([]byte(r.Password))
		if err != nil {
			return SavedServer{}, fmt.Errorf("не удалось сохранить SSH-пароль в защищённое хранилище: %w", err)
		}
		profile.PasswordBlob = base64.StdEncoding.EncodeToString(cipher)
		profile.HasPassword = len(profile.PasswordBlob) > 0
	}
	return profile, nil
}

func (s SavedServer) summary() SavedServer {
	copy := s
	copy.PasswordBlob = ""
	copy.HasPassword = s.HasPassword || s.PasswordBlob != ""
	return copy
}

func (s SavedServer) toLoadedProfile() (loadedProfile, error) {
	out := loadedProfile{
		ID:          s.ID,
		Name:        s.Name,
		Host:        s.Host,
		SSHPort:     s.SSHPort,
		Username:    s.Username,
		Auth:        s.Auth,
		KeyFile:     s.KeyFile,
		Protocol:    s.Protocol,
		Port:        s.Port,
		SNI:         s.SNI,
		LastUsed:    s.LastUsed,
		HasPassword: s.HasPassword || s.PasswordBlob != "",
	}
	if s.PasswordBlob == "" {
		return out, nil
	}
	cipher, err := base64.StdEncoding.DecodeString(s.PasswordBlob)
	if err != nil {
		return loadedProfile{}, fmt.Errorf("не удалось прочитать сохранённый пароль: %w", err)
	}
	plain, err := unprotectSecret(cipher)
	if err != nil {
		return loadedProfile{}, fmt.Errorf("не удалось расшифровать сохранённый пароль: %w", err)
	}
	out.Password = string(plain)
	return out, nil
}

func protocolLabel(v string) string {
	switch v {
	case "portline":
		return "Portline"
	case "vless":
		return "VLESS"
	case "hy2":
		return "Hysteria 2"
	default:
		return "Profile"
	}
}

func savedServersPath() (string, error) {
	root, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "profiles", "saved-servers.json"), nil
}

func loadSavedServers() ([]SavedServer, error) {
	path, err := savedServersPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []SavedServer{}, nil
	}
	if err != nil {
		return nil, err
	}
	var list []SavedServer
	if err = json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	sortSavedServers(list)
	return list, nil
}

func saveSavedServers(list []SavedServer) error {
	path, err := savedServersPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	sortSavedServers(list)
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return lockProfileFile(path)
}

func sortSavedServers(list []SavedServer) {
	sort.SliceStable(list, func(i, j int) bool {
		ai, aerr := time.Parse(time.RFC3339, list[i].LastUsed)
		aj, berr := time.Parse(time.RFC3339, list[j].LastUsed)
		if aerr == nil && berr == nil && !ai.Equal(aj) {
			return ai.After(aj)
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
}

func (a *App) saveServerProfile(input saveProfileRequest) (SavedServer, error) {
	if err := input.Validate(); err != nil {
		return SavedServer{}, err
	}
	profile, err := input.toSavedServer()
	if err != nil {
		return SavedServer{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if profile.ID == "" {
		profile.ID = randomHex(12)
	}
	updated := false
	for i := range a.savedServers {
		if a.savedServers[i].ID == profile.ID {
			if !input.SavePassword {
				profile.PasswordBlob = a.savedServers[i].PasswordBlob
				profile.HasPassword = a.savedServers[i].HasPassword || a.savedServers[i].PasswordBlob != ""
			}
			a.savedServers[i] = profile
			updated = true
			break
		}
	}
	if !updated {
		a.savedServers = append(a.savedServers, profile)
	}
	if err := saveSavedServers(a.savedServers); err != nil {
		return SavedServer{}, err
	}
	return profile.summary(), nil
}

func (a *App) deleteServerProfile(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("Не выбран профиль для удаления.")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := -1
	for i := range a.savedServers {
		if a.savedServers[i].ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return os.ErrNotExist
	}
	a.savedServers = append(a.savedServers[:idx], a.savedServers[idx+1:]...)
	return saveSavedServers(a.savedServers)
}

func (a *App) listServerProfiles() []SavedServer {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]SavedServer, 0, len(a.savedServers))
	for _, item := range a.savedServers {
		out = append(out, item.summary())
	}
	sortSavedServers(out)
	return out
}

func (a *App) loadServerProfile(id string) (loadedProfile, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return loadedProfile{}, errors.New("Не выбран профиль для загрузки.")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.savedServers {
		if a.savedServers[i].ID == id {
			return a.savedServers[i].toLoadedProfile()
		}
	}
	return loadedProfile{}, os.ErrNotExist
}
