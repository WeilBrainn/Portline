package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseGatewayInspection(t *testing.T) {
	cases := []struct {
		line                 string
		state, port, version string
		compatible           bool
	}{
		{"PORTLINE_GATEWAY|installed|active|8449|1.2.0|1|203.0.113.10", "installed", "8449", "1.2.0", true},
		{"PORTLINE_GATEWAY|missing|-|-|-|-|-", "missing", "-", "-", false},
		{"PORTLINE_GATEWAY|installed|inactive|8449|1.0.0|2|203.0.113.10", "installed", "8449", "1.0.0", false},
	}
	for _, tc := range cases {
		result, err := parseGatewayInspection(tc.line)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != tc.state || result.Port != tc.port || result.Version != tc.version || result.Compatible != tc.compatible {
			t.Fatalf("unexpected result: %+v", result)
		}
	}
	for _, line := range []string{"PORTLINE_GATEWAY|installed|active|notaport|1.2.0|1|host", "PORTLINE_GATEWAY|missing|extra", "PORTLINE_GATEWAY|installed|active|8449|1.2.0|1|host;touch /tmp/a"} {
		if _, err := parseGatewayInspection(line); err == nil {
			t.Fatalf("accepted invalid report %q", line)
		}
	}
}

func TestClassifySSHFailure(t *testing.T) {
	cases := []struct {
		logs []string
		want string
	}{
		{[]string{"Permission denied (publickey,password)."}, "аутентификац"},
		{[]string{"sudo: a password is required"}, "sudo"},
		{[]string{"gateway already configured on example.net:443"}, "конфигурац"},
		{[]string{"systemctl: Failed to start portline-gateway.service"}, "служб"},
	}
	for _, tc := range cases {
		got := classifySSHFailure(nil, tc.logs)
		if !strings.Contains(strings.ToLower(got), tc.want) {
			t.Errorf("%v: %s", tc.logs, got)
		}
	}
}

func TestGatewayUpdateRequiresExplicitConfirmation(t *testing.T) {
	a := &App{token: "secret"}
	r := requestOK()
	r.Protocol = "portline"
	r.Port = 8449
	b, _ := json.Marshal(r)
	req := httptest.NewRequest("POST", "http://127.0.0.1/api/gateway/update", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	a.serveHTTP(w, req)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "подтверждения") {
		t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
	}
}
