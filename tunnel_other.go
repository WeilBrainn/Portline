//go:build !windows

package main

import (
	"context"
	"errors"
	"portline/internal/ptunnel"
)

type nativeSession struct {
	tunnelTraffic
	guardMode string
	done      chan struct{}
}

func (s *nativeSession) Stop()                 {}
func (s *nativeSession) CleanupError() error   { return nil }
func (s *nativeSession) Done() <-chan struct{} { return s.done }
func startNativeTunnel(_ context.Context, _ ptunnel.Profile, _ func(string)) (*nativeSession, error) {
	return nil, errors.New("Встроенный системный туннель пока поддерживается только в Windows.")
}
func lockProfileFile(_ string) error { return nil }

var errFirewallDisabled = errors.New("firewall disabled")

func enableFirewall(_ context.Context) error {
	return errors.New("Управление брандмауэром доступно только в Windows.")
}

func recoverStartupRoutes() error { return nil }
