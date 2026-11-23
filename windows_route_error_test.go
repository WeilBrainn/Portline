package main

import (
	"strings"
	"testing"
)

func TestExplainWindowsRouteConflictOtherVPN(t *testing.T) {
	output := []byte("PORTLINE_ROUTE_CONFLICT|0.0.0.0/1|8|10.0.0.1|external\r\nAt line:1 char:1 + CategoryInfo: OperationStopped")
	message, ok := explainWindowsRouteConflict(output)
	if !ok {
		t.Fatal("expected conflict marker to be recognized")
	}
	for _, value := range []string{"0.0.0.0/1", "8", "другого VPN", "не удаляет"} {
		if !strings.Contains(message, value) {
			t.Fatalf("message should explain %q: %s", value, message)
		}
	}
	if strings.Contains(message, "CategoryInfo") {
		t.Fatalf("PowerShell stack leaked into user error: %s", message)
	}
}

func TestExplainWindowsRouteConflictOldPortline(t *testing.T) {
	output := []byte("PORTLINE_ROUTE_CONFLICT|128.0.0.0/1|23|0.0.0.0|portline\r\n")
	message, ok := explainWindowsRouteConflict(output)
	if !ok || !strings.Contains(message, "Portline") || !strings.Contains(message, "восстанов") {
		t.Fatalf("must identify stale Portline route: %q (found=%v)", message, ok)
	}
}

func TestExplainWindowsRouteConflictMalformedIsNotTrusted(t *testing.T) {
	for _, sample := range []string{
		"ordinary powershell error", "PORTLINE_ROUTE_CONFLICT|0.0.0.0/1|not-index|next|external",
		"PORTLINE_ROUTE_CONFLICT|127.0.0.0/8|8|next|external",
		"PORTLINE_ROUTE_CONFLICT|0.0.0.0/1|8|next|fake",
	} {
		if message, ok := explainWindowsRouteConflict([]byte(sample)); ok {
			t.Fatalf("false conflict for %q: %s", sample, message)
		}
	}
}
