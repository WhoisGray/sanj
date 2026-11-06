package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const gluetunBase = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/"

var gluetunProviders = []string{
	"airvpn", "cyberghost", "expressvpn", "fastestvpn", "giganews", "hidemyass",
	"ipvanish", "ivpn", "mullvad", "ovpn", "privado", "private internet access",
	"privatevpn", "protonvpn", "purevpn", "slickvpn", "surfshark", "torguard",
	"vpn unlimited", "vpnsecure", "vyprvpn", "windscribe",
}

type gluetunOpts struct {
	name, country, proto, ikeUser, ikeID, jsonPath, csvPath, xlsxPath string
	refresh                                                           bool
	ttl, ikeTimeout, tcpTimeout                                       time.Duration
	limit, conc                                                       int
	saw                                                               map[string]bool
}

func (o *gluetunOpts) seen(name string) {
	if o.saw == nil {
		o.saw = make(map[string]bool)
	}
	o.saw[name] = true
}

type gluetunServer struct {
	VPN        string   `json:"vpn"`
	Country    string   `json:"country"`
	Region     string   `json:"region"`
	City       string   `json:"city"`
	ServerName string   `json:"server_name"`
	Hostname   string   `json:"hostname"`
	WGPubKey   string   `json:"wgpubkey"`
	IPs        []string `json:"ips"`
	TCP        bool     `json:"tcp"`
	UDP        bool     `json:"udp"`
	PortsTCP   []int    `json:"ports_tcp"`
	PortsUDP   []int    `json:"ports_udp"`
	TCPPorts   []int    `json:"tcp_ports"`
	UDPPorts   []int    `json:"udp_ports"`
}

type gluetunCatalog struct {
	Version   int             `json:"version"`
	Timestamp int64           `json:"timestamp"`
	Servers   []gluetunServer `json:"servers"`
}

type gluetunCache struct {
	Version int            `json:"version"`
	Fetched time.Time      `json:"fetched"`
	Catalog gluetunCatalog `json:"catalog"`
}

func canonicalProvider(name string) (string, error) {
	name = strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(name))), " ")
	for _, valid := range gluetunProviders {
		if name == valid {
			return name, nil
		}
	}
	return "", fmt.Errorf("unknown provider %q (supported: %s)", name, strings.Join(gluetunProviders, ", "))
}

func gluetunCachePath(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return name + "-gluetun-cache.json", nil
	}
	dir := filepath.Join(home, ".cache", "nordike", "gluetun")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+"-v1.json"), nil
}

func readGluetunCache(path string, ttl time.Duration, now time.Time) (gluetunCatalog, time.Time, bool) {
	f, err := os.Open(path)
	if err != nil {
		return gluetunCatalog{}, time.Time{}, false
	}
	defer f.Close()
	var doc gluetunCache
	if err := json.NewDecoder(f).Decode(&doc); err != nil || doc.Version != 1 ||
		doc.Fetched.IsZero() || now.Sub(doc.Fetched) >= ttl || len(doc.Catalog.Servers) == 0 {
		return gluetunCatalog{}, time.Time{}, false
	}
	return doc.Catalog, doc.Fetched, true
}

func fetchGluetun(ctx context.Context, name string) (gluetunCatalog, error) {
	u := gluetunBase + url.PathEscape(name) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return gluetunCatalog{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vpnban/1")
	client := &http.Client{Timeout: 40 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return gluetunCatalog{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gluetunCatalog{}, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	var catalog gluetunCatalog
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&catalog); err != nil {
		return gluetunCatalog{}, err
	}
	if len(catalog.Servers) == 0 {
		return gluetunCatalog{}, errors.New("provider JSON contains no servers")
	}
	return catalog, nil
}

func loadGluetun(ctx context.Context, name string, refresh bool, ttl time.Duration) (gluetunCatalog, string, time.Time, error) {
	path, err := gluetunCachePath(name)
	if err != nil {
		return gluetunCatalog{}, "", time.Time{}, err
	}
	if !refresh {
		if c, fetched, ok := readGluetunCache(path, ttl, time.Now()); ok {
			return c, "cache " + path, fetched, nil
		}
	}
	c, err := fetchGluetun(ctx, name)
	if err != nil {
		if old, fetched, ok := readGluetunCache(path, 365*24*time.Hour, time.Now()); ok {
			fmt.Fprintf(os.Stderr, "download failed (%v); using stale cache\n", err)
			return old, "stale " + path, fetched, nil
		}
		return gluetunCatalog{}, "", time.Time{}, err
	}
	fetched := time.Now().UTC()
	if err := writeGluetunCache(path, c, fetched); err != nil {
		fmt.Fprintf(os.Stderr, "not caching: %v\n", err)
	}
	return c, "download", fetched, nil
}

func writeGluetunCache(path string, c gluetunCatalog, fetched time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(gluetunCache{Version: 1, Fetched: fetched, Catalog: c})
}

type gluetunTarget struct {
	server           nordServer
	udpPort, tcpPort int
	remoteID         string
}

func firstPort(values []int, fallback int) int {
	for _, p := range values {
		if p > 0 && p <= 65535 {
			return p
		}
	}
	return fallback
}

func gluetunTargets(name string, list []gluetunServer, country string, scan scanProtos, limit int, ikeID string) []gluetunTarget {
	qs := splitComma(country)
	var out []gluetunTarget
	for _, item := range list {
		if item.Hostname == "" {
			continue
		}
		if len(qs) > 0 {
			matched := false
			for _, q := range qs {
				if strings.EqualFold(item.Country, q) || strings.EqualFold(item.Region, q) || countryCodeMatches(q, item.Country, item.Region) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		s := nordServer{Name: firstNonEmpty(item.ServerName, item.Hostname), Hostname: item.Hostname,
			Country: firstNonEmpty(item.Country, item.Region), City: item.City, Status: "listed", WGPub: item.WGPubKey}
		// gluetun-servers publishes OpenVPN and WireGuard metadata, but no IKEv2 flag.
		// IKEv2 is an explicit discovery probe on the listed endpoint, including VPN Unlimited.
		switch item.VPN {
		case "wireguard":
			if item.WGPubKey != "" {
				s.Tech = append(s.Tech, "wireguard_udp")
			}
		case "openvpn":
			if item.UDP {
				s.Tech = append(s.Tech, "openvpn_udp")
			}
			if item.TCP {
				s.Tech = append(s.Tech, "openvpn_tcp")
			}
		}
		if !scan.onIKE() && !scan.match(s) {
			continue
		}
		s.Tech = orderTech(s.Tech)
		remoteID := item.Hostname
		if ikeID != "" {
			remoteID = ikeID
		}
		if name == "vpn unlimited" {
			// VPN Unlimited gateways use *.vpnunlimitedapp.com for transport, but
			// their IKEv2 certificate identity is ironnodes.com. Always send that Remote ID.
			remoteID = "ironnodes.com"
		}
		udpPort := firstPort(append(item.PortsUDP, item.UDPPorts...), portOUDP)
		tcpPort := firstPort(append(item.PortsTCP, item.TCPPorts...), portOTCP)
		for _, ip := range item.IPs {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil || poisoned(parsed) {
				continue
			}
			s.IP = ip
			out = append(out, gluetunTarget{server: s, udpPort: udpPort, tcpPort: tcpPort, remoteID: remoteID})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].server, out[j].server
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		return a.IP < b.IP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func runGluetun(o gluetunOpts) error {
	name, err := canonicalProvider(o.name)
	if err != nil {
		return err
	}
	if o.conc < 1 {
		o.conc = 1
	}
	if !o.saw["c"] {
		o.conc = 32
	}
	if !o.saw["ike-user"] {
		o.ikeUser = "this is health check"
	}
	if !o.saw["ike-id"] {
		o.ikeID = ""
	}
	if !o.saw["json"] {
		o.jsonPath = strings.ReplaceAll(name, " ", "-") + "-results.json"
	}
	if !o.saw["csv"] {
		o.csvPath = strings.ReplaceAll(name, " ", "-") + "-results.csv"
	}
	if !o.saw["xlsx"] {
		o.xlsxPath = strings.ReplaceAll(name, " ", "-") + "-results.xlsx"
	}
	scan, err := parseScanProtos(o.proto)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	c, source, fetched, err := loadGluetun(ctx, name, o.refresh, o.ttl)
	if err != nil {
		return err
	}
	targets := gluetunTargets(name, c.Servers, o.country, scan, o.limit, o.ikeID)
	fmt.Fprintf(os.Stderr, "%s: %d catalog entries from %s (%s), probing %d endpoints (%s), workers %d\n", name, len(c.Servers), source, fetched.Format(time.RFC3339), len(targets), scan.label(), o.conc)
	prime, _ := new(big.Int).SetString(modp2048, 16)
	if scan.onIKE() {
		warmIKE(prime, 32)
	}
	var pool *udpPool
	if scan.needsUDP() {
		poolN := o.conc / 8
		if poolN < 4 {
			poolN = 4
		}
		pool, err = newUDPPool(poolN)
		if err != nil {
			return err
		}
		defer pool.Close()
	}
	var mu sync.Mutex
	done := 0
	hits := parallel(targets, o.conc, func(t gluetunTarget) nordHit {
		h := probeGluetunTarget(ctx, pool, prime, t, scan, o)
		mu.Lock()
		done++
		if done%64 == 0 || done == len(targets) {
			progress(name, int64(done), int64(len(targets)))
		}
		mu.Unlock()
		return h
	})
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := freshRank(hits[i].Fresh, hits[i].Firewall), freshRank(hits[j].Fresh, hits[j].Firewall)
		if a != b {
			return a < b
		}
		return hits[i].rtt() < hits[j].rtt()
	})
	rows, cols := flattenNord(hits)
	if err := writeNord(o.jsonPath, o.csvPath, o.xlsxPath, "gluetun-servers/"+name+" ("+source+")", fetched, rows, cols); err != nil {
		return err
	}
	summarizeNord(hits)
	return nil
}

func probeGluetunTarget(ctx context.Context, pool *udpPool, prime *big.Int, t gluetunTarget, scan scanProtos, o gluetunOpts) nordHit {
	s := t.server
	h := nordHit{Server: s, HasWG: hasTech(s.Tech, "wireguard_udp"), HasOUDP: hasTech(s.Tech, "openvpn_udp"),
		HasOTCP: hasTech(s.Tech, "openvpn_tcp"), HasIKE: scan.onIKE(), WG: "skip", OUDP: "skip", OTCP: "skip", IKE: "skip",
		U53: "skip", T80: "skip", WGMS: -1, OUDPMS: -1, OTCPMS: -1, IKEMS: -1, U53MS: -1, T80MS: -1}
	if ctx.Err() != nil {
		h.Fresh, h.Firewall = "skip", "interrupted"
		return h
	}
	var wg sync.WaitGroup
	if h.HasWG && scan.onWG() {
		wg.Add(1)
		go func() { defer wg.Done(); h.WG, h.WGDetail, h.WGMS = probeWG(ctx, pool, s.IP, s.WGPub, o.ikeTimeout) }()
	}
	if h.HasOUDP && scan.onOUDP() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.OUDP, h.OUDPDetail, h.OUDPMS = probeOVPNUDP(ctx, pool, s.IP, t.udpPort, o.ikeTimeout)
		}()
	}
	if h.HasOTCP && scan.onOTCP() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.OTCP, h.OTCPDetail, h.OTCPMS = probeOVPNTCP(ctx, s.IP, t.tcpPort, o.tcpTimeout)
		}()
	}
	if scan.onIKE() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := probeIKE(s.IP, prime, o.ikeUser, t.remoteID, o.ikeTimeout)
			h.IKE = normIKE(r)
			h.IKEPhase1, h.IKEPhase2, h.IKEAuth = r.Phase1, r.Phase2, r.AuthStatus
			h.IKEPort = r.Port
			if r.RTT > 0 {
				h.IKEMS = int(r.RTT.Milliseconds())
			}
		}()
	}
	if scan.full {
		wg.Add(2)
		go func() {
			defer wg.Done()
			h.U53, h.U53Detail, h.U53MS = probeOVPNUDP(ctx, pool, s.IP, portDNS, o.ikeTimeout)
		}()
		go func() { defer wg.Done(); h.T80, h.T80Detail, h.T80MS = probeOVPNTCP(ctx, s.IP, portHTTP, o.tcpTimeout) }()
	}
	wg.Wait()
	h.Fresh, h.Firewall = scoreHit(h)
	return h
}
