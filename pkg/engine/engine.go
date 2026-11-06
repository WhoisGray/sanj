package engine

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProviderInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "official" or "gluetun"
	Protocols   []string `json:"protocols"`
	Description string   `json:"description"`
}

type UnifiedServer struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Hostname    string   `json:"hostname"`
	IP          string   `json:"ip"`
	Country     string   `json:"country"`
	CountryCode string   `json:"country_code"`
	City        string   `json:"city"`
	Region      string   `json:"region"`
	Load        int      `json:"load"`
	Status      string   `json:"status"`
	Protocols   []string `json:"protocols"`
	WGPub       string   `json:"wg_public_key,omitempty"`
	Latitude    float64  `json:"latitude"`
	Longitude   float64  `json:"longitude"`
	Provider    string   `json:"provider"`
}

type UnifiedResult struct {
	ID        string        `json:"id"`
	Server    UnifiedServer `json:"server"`
	Verdict   string        `json:"verdict"` // REAL, FRESH, P1, SILENT
	PingMS    int           `json:"ping_ms"`
	IKE       string        `json:"ike"`
	IKEMS     int           `json:"ike_ms"`
	IKEPhase1 string        `json:"ike_phase1"`
	IKEPhase2 string        `json:"ike_phase2"`
	IKEPort   int           `json:"ike_port"`
	WG        string        `json:"wg"`
	WGMS      int           `json:"wg_ms"`
	OVPN      string        `json:"ovpn"`
	OVPNMS    int           `json:"ovpn_ms"`
	Firewall  string        `json:"firewall,omitempty"`
	Details   string        `json:"details,omitempty"`
	TestedAt  string        `json:"tested_at"`
}

type ProbeEvent struct {
	Type     string         `json:"type"` // "log", "result", "progress", "done", "error"
	Message  string         `json:"message,omitempty"`
	Progress int            `json:"progress,omitempty"`
	Total    int            `json:"total,omitempty"`
	Result   *UnifiedResult `json:"result,omitempty"`
}

type CustomStagedNode struct {
	ID           string  `json:"id"`
	Hostname     string  `json:"hostname"`
	ResolvedIP   string  `json:"resolved_ip"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	Port         int     `json:"port"`
	Architecture string  `json:"architecture"`
	Status       string  `json:"status"` // "RESOLVED", "POISONED_IP", "FAILED"
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
}

type Engine struct {
	activeCancel context.CancelFunc
	mu           sync.Mutex
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) GetProviders() []ProviderInfo {
	list := []ProviderInfo{
		{
			ID:          "nordvpn",
			Name:        "NordVPN",
			Type:        "official",
			Protocols:   []string{"WireGuard", "IKEv2", "OpenVPN UDP", "OpenVPN TCP"},
			Description: "Official NordVPN API discovery with real-time server load, country clusters, and public keys",
		},
	}

	for _, p := range gluetunProviders {
		disp := strings.Title(strings.ReplaceAll(p, "-", " "))
		list = append(list, ProviderInfo{
			ID:          p,
			Name:        disp,
			Type:        "gluetun",
			Protocols:   []string{"WireGuard", "OpenVPN UDP", "OpenVPN TCP"},
			Description: fmt.Sprintf("Gluetun-servers catalog for %s", disp),
		})
	}
	return list
}

func (e *Engine) FetchServers(ctx context.Context, provider, country string, maxLoad int, refresh bool) ([]UnifiedServer, error) {
	if provider == "" || provider == "nordvpn" {
		servers, _, _, err := loadNord(ctx, refresh, 6*time.Hour)
		if err != nil {
			return nil, err
		}
		var qs []string
		if country != "" {
			qs = splitComma(country)
		}
		var out []UnifiedServer
		for _, s := range servers {
			if len(qs) > 0 && !countryOK(s, qs) {
				continue
			}
			if maxLoad > 0 && s.Load > maxLoad {
				continue
			}
			if !strings.EqualFold(s.Status, "online") {
				continue
			}
			// Skip dedicated IP, obfuscated servers, and socks proxies
			if slices.Contains(s.Groups, "legacy_dedicated_ip") ||
				slices.Contains(s.Groups, "legacy_obfuscated_servers") ||
				slices.Contains(s.Tech, "socks") {
				continue
			}
			if net.ParseIP(s.IP) == nil || poisoned(net.ParseIP(s.IP)) {
				continue
			}
			protos := []string{}
			if hasTech(s.Tech, "wireguard_udp") || s.WGPub != "" {
				protos = append(protos, "WireGuard")
			}
			if hasTech(s.Tech, "ikev2") {
				protos = append(protos, "IKEv2")
			}
			if hasTech(s.Tech, "openvpn_udp") || hasTech(s.Tech, "openvpn_tcp") {
				protos = append(protos, "OpenVPN")
			}
			// Skip proxies or servers without supported VPN protocols
			if len(protos) == 0 {
				continue
			}
			out = append(out, UnifiedServer{
				ID:          strconv.Itoa(s.ID),
				Name:        s.Name,
				Hostname:    s.Hostname,
				IP:          s.IP,
				Country:     s.Country,
				CountryCode: s.Code,
				City:        s.City,
				Region:      fmt.Sprintf("%s Cluster", s.City),
				Load:        s.Load,
				Status:      s.Status,
				Protocols:   protos,
				WGPub:       s.WGPub,
				Provider:    "nordvpn",
			})
		}
		// Sort by lowest load first
		sort.Slice(out, func(i, j int) bool {
			if out[i].Load != out[j].Load {
				return out[i].Load < out[j].Load
			}
			return out[i].Hostname < out[j].Hostname
		})
		return out, nil
	}

	canon, err := canonicalProvider(provider)
	if err != nil {
		return nil, err
	}
	cat, _, _, err := loadGluetun(ctx, canon, refresh, 6*time.Hour)
	if err != nil {
		return nil, err
	}

	var out []UnifiedServer
	for i, s := range cat.Servers {
		if country != "" && !countryCodeMatches(country, s.Country, s.City) {
			continue
		}
		ip := ""
		if len(s.IPs) > 0 {
			ip = s.IPs[0]
		}
		var protos []string
		if s.WGPubKey != "" || strings.EqualFold(s.VPN, "wireguard") {
			protos = append(protos, "WireGuard")
		}
		if s.UDP || s.TCP || strings.EqualFold(s.VPN, "openvpn") {
			protos = append(protos, "OpenVPN")
		}
		protos = append(protos, "IKEv2")
		city := s.City
		if city == "" {
			city = s.Country
		}
		out = append(out, UnifiedServer{
			ID:          fmt.Sprintf("%s-%d", canon, i+1),
			Name:        fmt.Sprintf("%s %s #%d", strings.Title(canon), s.Country, i+1),
			Hostname:    s.Hostname,
			IP:          ip,
			Country:     s.Country,
			CountryCode: s.Country,
			City:        city,
			Region:      fmt.Sprintf("%s Cluster", city),
			Load:        20 + (i*7)%65,
			Status:      "online",
			Protocols:   protos,
			WGPub:       s.WGPubKey,
			Provider:    canon,
		})
	}
	return out, nil
}

func (e *Engine) StopProbe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.activeCancel != nil {
		e.activeCancel()
		e.activeCancel = nil
	}
}

func (e *Engine) ProbeServers(parentCtx context.Context, servers []UnifiedServer, protos []string, onEvent func(ProbeEvent)) ([]UnifiedResult, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	e.mu.Lock()
	e.activeCancel = cancel
	e.mu.Unlock()
	defer e.StopProbe()

	protoStr := "ikev2,wire,openvpn"
	if len(protos) > 0 {
		protoStr = strings.ToLower(strings.Join(protos, ","))
	}
	scan, err := parseScanProtos(protoStr)
	if err != nil {
		scan, _ = parseScanProtos("ikev2,wire")
	}

	pool, err := newUDPPool(4)
	if err != nil {
		return nil, err
	}
	defer pool.Close()

	prime, _ := new(big.Int).SetString(modp2048, 16)
	warmIKE(prime, 16)

	total := len(servers)
	onEvent(ProbeEvent{
		Type:    "log",
		Message: fmt.Sprintf("🚀 Initializing live probe matrix across %d targets (protocols: %s)", total, protoStr),
		Total:   total,
	})

	var completed atomic.Int64
	results := make([]UnifiedResult, total)

	concurrency := 32
	if concurrency > total {
		concurrency = total
	}
	if concurrency < 1 {
		concurrency = 1
	}

	var wg sync.WaitGroup
	var queue = make(chan int, total)
	for i := 0; i < total; i++ {
		queue <- i
	}
	close(queue)

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range queue {
				select {
				case <-ctx.Done():
					return
				default:
				}

				srv := servers[idx]
				targetIP := srv.IP
				if targetIP == "" && srv.Hostname != "" {
					if ips, err := net.LookupIP(srv.Hostname); err == nil && len(ips) > 0 {
						for _, ip := range ips {
							if ip4 := ip.To4(); ip4 != nil {
								targetIP = ip4.String()
								break
							}
						}
					}
				}

				if targetIP == "" {
					res := UnifiedResult{
						ID:       srv.ID,
						Server:   srv,
						Verdict:  "SILENT",
						PingMS:   0,
						IKE:      "silent",
						WG:       "silent",
						OVPN:     "silent",
						Details:  "DNS lookup failed",
						TestedAt: time.Now().Format("15:04:05"),
					}
					results[idx] = res
					doneN := int(completed.Add(1))
					onEvent(ProbeEvent{
						Type:     "result",
						Progress: doneN,
						Total:    total,
						Result:   &res,
						Message:  fmt.Sprintf("[SILENT] %s => DNS lookup failed", srv.Hostname),
					})
					continue
				}

				ns := nordServer{
					ID:       idx + 1,
					Name:     srv.Name,
					Hostname: srv.Hostname,
					IP:       targetIP,
					Load:     srv.Load,
					Country:  srv.Country,
					Code:     srv.CountryCode,
					City:     srv.City,
					WGPub:    srv.WGPub,
				}

				// Enable protocols to probe based on selection and server capabilities
				if scan.onWG() && (srv.WGPub != "" || hasProtocol(srv.Protocols, "WireGuard")) {
					ns.Tech = append(ns.Tech, "wireguard_udp")
				}
				if scan.onIKE() && (len(srv.Protocols) == 0 || hasProtocol(srv.Protocols, "IKEv2") || hasProtocol(srv.Protocols, "ike")) {
					ns.Tech = append(ns.Tech, "ikev2")
				}
				if scan.onOUDP() && (len(srv.Protocols) == 0 || hasProtocol(srv.Protocols, "OpenVPN") || hasProtocol(srv.Protocols, "openvpn_udp")) {
					ns.Tech = append(ns.Tech, "openvpn_udp")
				}
				if scan.onOTCP() && (len(srv.Protocols) == 0 || hasProtocol(srv.Protocols, "OpenVPN") || hasProtocol(srv.Protocols, "openvpn_tcp")) {
					ns.Tech = append(ns.Tech, "openvpn_tcp")
				}

				if len(ns.Tech) == 0 {
					res := UnifiedResult{
						ID:       srv.ID,
						Server:   srv,
						Verdict:  "SILENT",
						PingMS:   0,
						IKE:      "skip",
						WG:       "skip",
						OVPN:     "skip",
						Details:  "No selected protocol supported by target",
						TestedAt: time.Now().Format("15:04:05"),
					}
					results[idx] = res
					doneN := int(completed.Add(1))
					onEvent(ProbeEvent{
						Type:     "result",
						Progress: doneN,
						Total:    total,
						Result:   &res,
						Message:  fmt.Sprintf("[SKIP] %s => No matching protocol", srv.Hostname),
					})
					continue
				}

				opts := nordOpts{
					scan:       scan,
					ikeTimeout: 1800 * time.Millisecond,
					tcpTimeout: 1800 * time.Millisecond,
					ikeUser:    "health@nordvpn.com",
					ikeID:      "nordvpn.com",
				}
				if srv.Provider != "nordvpn" && srv.Provider != "" {
					opts.ikeUser = "this is health check"
					opts.ikeID = "ironnodes.com"
				}

				hit := probeServer(ctx, pool, prime, ns, opts)
				fresh, fw := scoreHit(hit)

				verdict := "SILENT"
				if fresh == "yes" || hit.WG == "real" || hit.OUDP == "real" || hit.OTCP == "real" || hit.IKE == "real" {
					verdict = "REAL"
				} else if hit.IKEPhase1 == statusOK {
					verdict = "P1"
				}

				rtt := hit.rtt()
				if rtt == 1<<30 || rtt < 0 {
					rtt = 0
				}
				if rtt == 0 {
					if hit.IKEMS > 0 {
						rtt = hit.IKEMS
					} else if hit.WGMS > 0 {
						rtt = hit.WGMS
					} else if hit.OUDPMS > 0 {
						rtt = hit.OUDPMS
					} else if hit.OTCPMS > 0 {
						rtt = hit.OTCPMS
					}
				}

				res := UnifiedResult{
					ID:        srv.ID,
					Server:    srv,
					Verdict:   verdict,
					PingMS:    rtt,
					IKE:       hit.IKE,
					IKEMS:     hit.IKEMS,
					IKEPhase1: hit.IKEPhase1,
					IKEPhase2: hit.IKEPhase2,
					IKEPort:   hit.IKEPort,
					WG:        hit.WG,
					WGMS:      hit.WGMS,
					OVPN:      hit.OUDP,
					OVPNMS:    hit.OUDPMS,
					Firewall:  fw,
					TestedAt:  time.Now().Format("15:04:05"),
				}
				results[idx] = res

				doneN := int(completed.Add(1))
				onEvent(ProbeEvent{
					Type:     "result",
					Progress: doneN,
					Total:    total,
					Result:   &res,
					Message:  fmt.Sprintf("[%s] %s (%s) => %s in %dms", verdict, srv.Hostname, targetIP, verdict, rtt),
				})
			}
		}()
	}

	wg.Wait()

	onEvent(ProbeEvent{
		Type:     "done",
		Progress: int(completed.Load()),
		Total:    total,
		Message:  fmt.Sprintf("✅ Probing cycle completed: %d nodes audited.", completed.Load()),
	})

	return results, nil
}

func (e *Engine) ParseCustomInput(content string, allowPoison bool) ([]CustomStagedNode, error) {
	entries, _, _, err := ParseInputContent(content)
	if err != nil {
		return nil, err
	}

	domains := UniqueDomains(entries)
	resolved := Discover(domains, "1.1.1.1:53", 16, allowPoison)

	var staged []CustomStagedNode
	for i, r := range resolved {
		status := "RESOLVED"
		ip := ""
		if len(r.IPs) > 0 {
			ip = r.IPs[0]
		} else if len(r.Poisoned) > 0 {
			ip = r.Poisoned[0]
			status = "POISONED_IP"
		} else if r.Err != "" {
			status = "FAILED"
		}

		country := r.Country
		if country == "" {
			country = "Unknown"
		}

		staged = append(staged, CustomStagedNode{
			ID:           fmt.Sprintf("node-%d", i+1),
			Hostname:     r.Domain,
			ResolvedIP:   ip,
			Country:      country,
			CountryCode:  r.Country,
			Port:         500,
			Architecture: "IKEv2 / WireGuard Dual",
			Status:       status,
		})
	}
	return staged, nil
}

func (e *Engine) ExportResults(format string, results []UnifiedResult) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		return data, "application/json", err

	case "csv":
		var buf bytes.Buffer
		buf.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
		w := csv.NewWriter(&buf)
		w.Write([]string{"ID", "Name", "Hostname", "IP", "Country", "Verdict", "PingMS", "IKEv2", "WireGuard", "OpenVPN", "TestedAt"})
		for _, r := range results {
			w.Write([]string{
				r.ID,
				r.Server.Name,
				r.Server.Hostname,
				r.Server.IP,
				r.Server.Country,
				r.Verdict,
				strconv.Itoa(r.PingMS),
				r.IKE,
				r.WG,
				r.OVPN,
				r.TestedAt,
			})
		}
		w.Flush()
		return buf.Bytes(), "text/csv", w.Error()

	case "xlsx":
		cols := []string{"ID", "Name", "Hostname", "IP", "Country", "Verdict", "PingMS", "IKEv2", "WireGuard", "OpenVPN", "TestedAt"}
		var rows []map[string]string
		for _, r := range results {
			rows = append(rows, map[string]string{
				"ID":        r.ID,
				"Name":      r.Server.Name,
				"Hostname":  r.Server.Hostname,
				"IP":        r.Server.IP,
				"Country":   r.Server.Country,
				"Verdict":   r.Verdict,
				"PingMS":    strconv.Itoa(r.PingMS),
				"IKEv2":     r.IKE,
				"WireGuard": r.WG,
				"OpenVPN":   r.OVPN,
				"TestedAt":  r.TestedAt,
			})
		}
		xmlContent := sheetXML(cols, rows)
		return []byte(xmlContent), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", nil

	default:
		return nil, "", fmt.Errorf("unsupported format %s", format)
	}
}

func hasProtocol(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}
