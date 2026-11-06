package engine

import (
	"context"
	"testing"
	"time"
)

func TestEngineProbeRealServer(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	servers, err := eng.FetchServers(ctx, "nordvpn", "se", 100, false)
	if err != nil {
		t.Fatalf("FetchServers failed: %v", err)
	}
	if len(servers) == 0 {
		t.Fatalf("No servers found for Sweden")
	}

	targets := servers
	if len(targets) > 2 {
		targets = targets[:2]
	}

	results, err := eng.ProbeServers(ctx, targets, []string{"wireguard", "ikev2", "openvpn"}, func(ev ProbeEvent) {
		t.Logf("Event: type=%s msg=%s", ev.Type, ev.Message)
	})
	if err != nil {
		t.Fatalf("ProbeServers failed: %v", err)
	}
	for i, r := range results {
		t.Logf("Result %d: [%s] %s (%s) ping=%dms ike=%s wg=%s ovpn=%s",
			i, r.Verdict, r.Server.Hostname, r.Server.IP, r.PingMS, r.IKE, r.WG, r.OVPN)
	}
}

func TestEngineCustomInputParseAndProbe(t *testing.T) {
	eng := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	input := "186.247.168.146\n185.236.203.91\n"
	staged, err := eng.ParseCustomInput(input, false)
	if err != nil {
		t.Fatalf("ParseCustomInput failed: %v", err)
	}
	if len(staged) != 2 {
		t.Fatalf("expected 2 staged nodes, got %d", len(staged))
	}

	var targets []UnifiedServer
	for _, n := range staged {
		targets = append(targets, UnifiedServer{
			ID:        n.ID,
			Name:      n.Hostname,
			Hostname:  n.Hostname,
			IP:        n.ResolvedIP,
			Protocols: []string{"WireGuard", "IKEv2", "OpenVPN"},
		})
		break
	}

	results, err := eng.ProbeServers(ctx, targets, []string{"ikev2"}, func(ev ProbeEvent) {
		t.Logf("Custom probe event: type=%s msg=%s", ev.Type, ev.Message)
	})
	if err != nil {
		t.Fatalf("Custom probe failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

