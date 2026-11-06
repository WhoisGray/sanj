package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadHostList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.txt")
	body := "\uFEFF# comment\r\n\r\n" +
		"AE1.vpnunlimitedapp.com\r\n" +
		"ae1.vpnunlimitedapp.com\r\n" +
		"https://Br1.vpnunlimitedapp.com/path # note\r\n" +
		"us-sf10.vpnunlimitedapp.com:443, 1.2.3.4\r\n" +
		"not a host\r\n" +
		"10.10.0.5\r\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, probes, kind, err := loadInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "catalog" || len(probes) != 0 {
		t.Fatalf("kind=%s probes=%d", kind, len(probes))
	}
	want := []string{
		"ae1.vpnunlimitedapp.com",
		"br1.vpnunlimitedapp.com",
		"us-sf10.vpnunlimitedapp.com",
		"1.2.3.4",
		"10.10.0.5",
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(want), domainsOf(entries))
	}
	for i, domain := range want {
		if entries[i].Domain != domain || entries[i].Name != domain || entries[i].Source != "txt" {
			t.Fatalf("entry %d = %+v", i, entries[i])
		}
		if entries[i].Fields["domain"] != domain || entries[i].Fields["source"] != "txt" {
			t.Fatalf("fields %d = %+v", i, entries[i].Fields)
		}
	}
}

func TestLoadHostListRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# only a comment\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadInput(path); err == nil {
		t.Fatal("expected an error for a text file with no hosts")
	}
}

func TestLoadJSONCatalogStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	body := `{"servers":[{"domain":"Ae1.Example.com","name":"AE","country_code":"AE","is_healthy":true}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, _, kind, err := loadInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "catalog" || len(entries) != 1 || entries[0].Domain != "ae1.example.com" {
		t.Fatalf("kind=%s entries=%+v", kind, entries)
	}
}

func TestDiscoverLiteralIPv4SkipsDNS(t *testing.T) {
	rows := discover([]entry{{Domain: "1.2.3.4", Name: "1.2.3.4"}}, "127.0.0.1:1", 1, false)
	if len(rows) != 1 || len(rows[0].IPs) != 1 || rows[0].IPs[0] != "1.2.3.4" || len(rows[0].Poisoned) != 0 {
		t.Fatalf("public ip: %+v", rows)
	}
	rows = discover([]entry{{Domain: "10.10.0.1", Name: "10.10.0.1"}}, "127.0.0.1:1", 1, false)
	if len(rows) != 1 || len(rows[0].IPs) != 0 || len(rows[0].Poisoned) != 1 || rows[0].Poisoned[0] != "10.10.0.1" {
		t.Fatalf("poisoned ip: %+v", rows)
	}
	rows = discover([]entry{{Domain: "10.10.0.1", Name: "10.10.0.1"}}, "127.0.0.1:1", 1, true)
	if len(rows) != 1 || len(rows[0].IPs) != 1 || rows[0].IPs[0] != "10.10.0.1" {
		t.Fatalf("allow poisoned: %+v", rows)
	}
}

func TestLoadServerTxt(t *testing.T) {
	path := filepath.Join("..", "bin", "server.txt")
	if _, err := os.Stat(path); err != nil {
		t.Skip("local catalog not in the checkout:", path)
	}
	entries, probes, kind, err := loadInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "catalog" || len(probes) != 0 {
		t.Fatalf("kind=%s probes=%d", kind, len(probes))
	}
	if len(entries) < 1000 {
		t.Fatalf("parsed %d hosts from server.txt", len(entries))
	}
	seen := map[string]bool{}
	for _, item := range entries {
		if !strings.HasSuffix(item.Domain, ".vpnunlimitedapp.com") {
			t.Fatalf("unexpected host %q", item.Domain)
		}
		if seen[item.Domain] {
			t.Fatalf("duplicate %q", item.Domain)
		}
		seen[item.Domain] = true
		if item.Source != "txt" || item.Name != item.Domain {
			t.Fatalf("entry %+v", item)
		}
	}
}

func domainsOf(entries []entry) []string {
	out := make([]string, len(entries))
	for i, item := range entries {
		out[i] = item.Domain
	}
	return out
}
