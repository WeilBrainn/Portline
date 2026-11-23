package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"portline/internal/ptunnel"
	"regexp"
	"strings"
)

// routeJournal records precisely the interfaces and addresses modified by Portline.
// It is written and synced before any route is changed, then cleared only after
// confirmed cleanup. It also supports recovery after the application is killed.
type adapterDNSRecord struct {
	InterfaceIndex int      `json:"interfaceIndex"`
	StaticDNS      []string `json:"staticDNS,omitempty"`
}

type routeJournal struct {
	DNSGuardID        string             `json:"dnsGuardID,omitempty"`
	ClientIP          string             `json:"clientIP,omitempty"`
	Version           int                `json:"version"`
	Endpoint          string             `json:"endpoint"`
	EndpointPort      int                `json:"endpointPort,omitempty"`
	PhysicalInterface int                `json:"physicalInterface"`
	PhysicalGateway   string             `json:"physicalGateway"`
	TunnelInterface   int                `json:"tunnelInterface"`
	TunnelGUID        string             `json:"tunnelGUID"`
	PreviousMTU       int                `json:"previousMTU"`
	StaticDNS         []string           `json:"staticDNS"`
	AdapterDNS        []adapterDNSRecord `json:"adapterDNS,omitempty"`
	// GuardMode is "firewall" (default, also for older journals) or "routes".
	GuardMode    string `json:"guardMode,omitempty"`
	IPv6Adapters []int  `json:"ipv6Adapters,omitempty"`
}

var adapterGUIDPattern = regexp.MustCompile(`(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$`)

func (r routeJournal) validate() error {
	if (r.Version == 1 && r.ClientIP != "") || (r.Version == 2 && !ptunnel.ValidClientIP(r.ClientIP)) || ((r.Version == 3 || r.Version == 4) && r.ClientIP != "" && !ptunnel.ValidClientIP(r.ClientIP)) {
		return errors.New("invalid tunnel client address")
	}
	if ((r.Version == 3 || r.Version == 4) && !adapterGUIDPattern.MatchString(r.DNSGuardID)) || (r.Version != 3 && r.Version != 4 && r.DNSGuardID != "") {
		return errors.New("invalid DNS guard recovery record")
	}
	if r.Version == 4 && (r.EndpointPort < 1 || r.EndpointPort > 65535) {
		return errors.New("invalid endpoint port in network recovery record")
	}
	if (r.Version < 1 || r.Version > 4) || r.PhysicalInterface <= 0 || r.TunnelInterface <= 0 || r.PhysicalInterface == r.TunnelInterface || r.PreviousMTU < 576 || r.PreviousMTU > 65535 || !adapterGUIDPattern.MatchString(r.TunnelGUID) {
		return errors.New("invalid network recovery record")
	}
	for _, ip := range append([]string{r.Endpoint, r.PhysicalGateway}, r.StaticDNS...) {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil || strings.ContainsAny(ip, "\r\n\x00") {
			return errors.New("invalid IPv4 address in network recovery record")
		}
	}
	if r.GuardMode != "" && r.GuardMode != "firewall" && r.GuardMode != "routes" {
		return errors.New("invalid guard mode in network recovery record")
	}
	for _, idx := range r.IPv6Adapters {
		if idx <= 0 || idx == r.TunnelInterface {
			return errors.New("invalid IPv6 adapter record")
		}
	}
	for _, rec := range r.AdapterDNS {
		if rec.InterfaceIndex <= 0 || rec.InterfaceIndex == r.TunnelInterface {
			return errors.New("invalid adapter DNS record")
		}
		for _, ip := range rec.StaticDNS {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil || strings.ContainsAny(ip, "\r\n\x00") {
				return errors.New("invalid adapter DNS IPv4 address")
			}
		}
	}
	return nil
}

func storeRouteJournal(path string, state routeJournal) error {
	if err := state.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("existing network recovery record must be restored before connecting")
	}
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func readRouteJournal(path string) (routeJournal, bool, error) {
	var state routeJournal
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, true, err
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return state, true, fmt.Errorf("recovery record is corrupt: %w", err)
	}
	if err = state.validate(); err != nil {
		return state, true, err
	}
	return state, true, nil
}

// recoverRoutes must be called at startup and before any new connection.
// If cleanup fails the journal remains, so the user can retry as admin.
func recoverRoutes(path string, undo func(routeJournal) error) error {
	state, exists, err := readRouteJournal(path)
	if err != nil || !exists {
		return err
	}
	if undo == nil {
		return errors.New("no network rollback available")
	}
	if err := undo(state); err != nil {
		return fmt.Errorf("restoring network routes: %w", err)
	}
	return os.Remove(path)
}

func beginRoutes(path string, state routeJournal, apply func(routeJournal) error, undo func(routeJournal) error) error {
	if err := storeRouteJournal(path, state); err != nil {
		return err
	}
	if err := apply(state); err != nil {
		if restoreErr := recoverRoutes(path, undo); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("network restoration failed (journal preserved): %w", restoreErr))
		}
		return err
	}
	return nil
}
