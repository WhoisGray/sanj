package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// version is overwritten by the release build with -X main.version=v1.0.0.
var version = "dev"

type entry struct {
	Source      string            `json:"source"`
	Domain      string            `json:"domain"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Region      string            `json:"region,omitempty"`
	Country     string            `json:"country_code,omitempty"`
	Flag        string            `json:"flag,omitempty"`
	Latitude    string            `json:"latitude,omitempty"`
	Longitude   string            `json:"longitude,omitempty"`
	Healthy     *bool             `json:"healthy,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
}

type resolved struct {
	entry
	IPs      []string `json:"ips"`
	Poisoned []string `json:"poisoned,omitempty"`
	Err      string   `json:"error,omitempty"`
}

type probe struct {
	Name        string            `json:"name"`
	Domain      string            `json:"domain"`
	IP          string            `json:"ip"`
	Region      string            `json:"region,omitempty"`
	Description string            `json:"description,omitempty"`
	Country     string            `json:"country_code,omitempty"`
	Flag        string            `json:"flag,omitempty"`
	MinMS       *int              `json:"min_ms"`
	AvgMS       *int              `json:"avg_ms"`
	MaxMS       *int              `json:"max_ms"`
	Reachable   bool              `json:"reachable"`
	IKEv2       bool              `json:"ikev2"`
	IKEPort     *int              `json:"ike_port"`
	IKEMS       *int              `json:"ike_ms"`
	Phase1      string            `json:"phase1"`
	Phase2      string            `json:"phase2"`
	AuthStatus  string            `json:"auth_status"`
	Fields      map[string]string `json:"fields,omitempty"`
}

func main() {
	file := flag.String("file", "", "servers.json, a text file of hosts (one per line), or sanj-results.json")
	phase := flag.String("phase", "", "1 discover, 2 probe, all both. Empty: phase 2 when no file, both when the file is a catalog")
	conc := flag.Int("c", 80, "number of concurrent workers")
	dnsAddr := flag.String("dns", "1.1.1.1:53", "DNS server")
	ikeTimeout := flag.Duration("ike-timeout", 1000*time.Millisecond, "IKEv2 timeout")
	tcpTimeout := flag.Duration("tcp-timeout", 1200*time.Millisecond, "TCP connect timeout")
	ikeUser := flag.String("ike-user", "this is health check", "user identity for IKE_AUTH")
	ikeID := flag.String("ike-id", "ironnodes.com", "remote ID for IKE_AUTH")
	jsonOut := flag.String("json", "sanj-results.json", "JSON output path")
	xlsxOut := flag.String("xlsx", "sanj-results.xlsx", "Excel output path")
	csvOut := flag.String("csv", "sanj-results.csv", "CSV output path")
	allowPoison := flag.Bool("allow-poisoned", false, "keep going even when DNS returns a private address such as 10.10")
	nordMode := flag.Bool("nord", false, "Fetch the NordVPN server list and probe the protocols in -proto")
	proto := flag.String("proto", "ikev2", "ikev2 (default), wire, openvpn, a comma list such as ikev2,wire, or full")
	refresh := flag.Bool("refresh", false, "Ignore the NordVPN cache and download again")
	ttl := flag.Duration("ttl", 6*time.Hour, "NordVPN cache lifetime")
	limitN := flag.Int("limit", 0, "Probe at most this many NordVPN servers, lowest load first")
	country := flag.String("country", "", "NordVPN country code or name, comma-separated")
	maxLoad := flag.Int("load", 100, "Skip NordVPN servers above this load")
	offline := flag.Bool("offline", false, "Also probe NordVPN servers that are not online")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	if *nordMode {
		opts := nordOpts{
			refresh: *refresh, ttl: *ttl, limit: *limitN, conc: *conc,
			country: *country, maxLoad: *maxLoad, offline: *offline,
			proto:      *proto,
			ikeTimeout: *ikeTimeout, tcpTimeout: *tcpTimeout,
			ikeUser: *ikeUser, ikeID: *ikeID,
			jsonPath: *jsonOut, csvPath: *csvOut, xlsxPath: *xlsxOut,
		}
		flag.Visit(func(f *flag.Flag) { opts.seen(f.Name) })
		if err := runNord(opts); err != nil {
			fmt.Fprintln(os.Stderr, "❌", err)
			os.Exit(1)
		}
		return
	}

	if *file == "" && *phase == "" {
		if _, err := os.Stat("sanj-results.json"); err == nil {
			*file = "sanj-results.json"
			*phase = "2"
		} else {
			usage()
			os.Exit(2)
		}
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "❌ input file is required")
		os.Exit(2)
	}

	entries, saved, kind, err := loadInput(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mode := *phase
	if mode == "" {
		if kind == "catalog" {
			mode = "all"
		} else {
			mode = "2"
		}
	}

	var found []resolved
	if mode == "1" || mode == "all" {
		if kind != "catalog" {
			fmt.Fprintln(os.Stderr, "❌ phase 1 only runs on a domain catalog (server JSON or a text file)")
			os.Exit(2)
		}
		domains := uniqueDomains(entries)
		fmt.Fprintf(os.Stderr, "🔍 phase 1: resolving %d domains via %s with %d workers\n", len(domains), *dnsAddr, *conc)
		found = discover(domains, *dnsAddr, *conc, *allowPoison)
		poisonOnly := 0
		public := 0
		for _, row := range found {
			public += len(row.IPs)
			if len(row.IPs) == 0 && len(row.Poisoned) > 0 {
				poisonOnly++
			}
		}
		if public == 0 && poisonOnly > 0 && !*allowPoison {
			fmt.Fprintf(os.Stderr, "🛑 VPN is on: %d domains returned only a private address (such as 10.10). Turn the VPN off and run again.\n", poisonOnly)
			os.Exit(3)
		}
		if poisonOnly > 0 {
			fmt.Fprintf(os.Stderr, "⚠️ warning: %d domains had spoofed answers and were skipped.\n", poisonOnly)
		}
		fmt.Fprintf(os.Stderr, "✅ phase 1 done: %d public addresses\n", public)
		if mode == "1" {
			writeAll(*jsonOut, *xlsxOut, *csvOut, entries, nil, found)
			return
		}
		saved = targetsFrom(found)
	}

	if len(saved) == 0 {
		if kind == "catalog" {
			fmt.Fprintln(os.Stderr, "❌ this file is only a catalog and has no discovered addresses; run with -phase all (or -phase 1).")
		} else {
			fmt.Fprintln(os.Stderr, "❌ no addresses to probe")
		}
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "📡 phase 2: probing %d addresses, concurrency %d\n", len(saved), *conc)
	probes := scan(saved, *conc, *ikeUser, *ikeID, *ikeTimeout, *tcpTimeout)
	sort.SliceStable(probes, func(i, j int) bool {
		ai, aj := math.MaxInt, math.MaxInt
		if probes[i].AvgMS != nil {
			ai = *probes[i].AvgMS
		}
		if probes[j].AvgMS != nil {
			aj = *probes[j].AvgMS
		}
		return ai < aj
	})
	writeAll(*jsonOut, *xlsxOut, *csvOut, entries, probes, found)
	summarize(probes)
}

func usage() {
	fmt.Fprintf(os.Stderr, "📡 nordvpn checker (%s)\n", version)
	fmt.Fprintln(os.Stderr, "  sanj -nord                         IKEv2 only")
	fmt.Fprintln(os.Stderr, "  sanj -nord -proto wire")
	fmt.Fprintln(os.Stderr, "  sanj -nord -proto ikev2,wire")
	fmt.Fprintln(os.Stderr, "  sanj -nord -proto full")
	fmt.Fprintln(os.Stderr, "  sanj -nord -refresh -c 256 -country se -limit 40")
	fmt.Fprintln(os.Stderr, "  sanj -file servers.json")
	fmt.Fprintln(os.Stderr, "  sanj -file server.txt          one domain or IPv4 per line")
	fmt.Fprintln(os.Stderr, "  sanj                         phase 2 on sanj-results.json")
}

func loadInput(path string) ([]entry, []probe, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", err
	}
	trim := strings.TrimSpace(strings.TrimPrefix(string(raw), "\uFEFF"))
	if trim == "" {
		return nil, nil, "", fmt.Errorf("file is empty")
	}
	if !strings.HasPrefix(trim, "{") && !strings.HasPrefix(trim, "[") {
		entries := readHostList(trim)
		if len(entries) == 0 {
			return nil, nil, "", fmt.Errorf("no valid domain found in the text file")
		}
		return entries, nil, "catalog", nil
	}
	if strings.HasPrefix(trim, "[") {
		var list []map[string]any
		if err := json.Unmarshal([]byte(trim), &list); err != nil {
			return nil, nil, "", err
		}
		return nil, probesFromMaps(list), "list", nil
	}
	var bag map[string]any
	if err := json.Unmarshal([]byte(trim), &bag); err != nil {
		return nil, nil, "", err
	}
	if _, ok := bag["servers"]; ok || bag["stream_servers"] != nil {
		return readCatalog(bag), nil, "catalog", nil
	}
	if catalog, ok := bag["catalog"]; ok {
		if entries := readSavedCatalog(catalog); len(entries) > 0 {
			return entries, nil, "catalog", nil
		}
	}
	type stored struct {
		Probes    []probe    `json:"probes"`
		Discovery []resolved `json:"discovery"`
	}
	var doc stored
	if err := json.Unmarshal([]byte(trim), &doc); err != nil {
		return nil, nil, "", err
	}
	if len(doc.Probes) > 0 {
		return nil, doc.Probes, "results", nil
	}
	if len(doc.Discovery) > 0 {
		return nil, targetsFrom(doc.Discovery), "results", nil
	}
	if rows, ok := bag["rows"].([]any); ok {
		return nil, probesFromAny(rows), "results", nil
	}
	return nil, nil, "", fmt.Errorf("unrecognized file format")
}

// readHostList reads a text file like server.txt: one domain or IPv4 per line.
// Blank lines and # comments are ignored. Several hosts on one line may be separated by spaces or commas.
func readHostList(text string) []entry {
	var out []entry
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.NewReplacer(",", " ", ";", " ").Replace(line)
		for _, token := range strings.Fields(line) {
			host, ok := normalizeHost(token)
			if !ok || seen[host] {
				continue
			}
			seen[host] = true
			out = append(out, entry{
				Source: "txt",
				Domain: host,
				Name:   host,
				Fields: map[string]string{
					"source": "txt",
					"domain": host,
					"name":   host,
				},
			})
		}
	}
	return out
}

func normalizeHost(raw string) (string, bool) {
	s := strings.Trim(strings.TrimSpace(raw), "\"'`")
	if s == "" {
		return "", false
	}
	lower := strings.ToLower(s)
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(lower, prefix) {
			s = s[len(prefix):]
			lower = lower[len(prefix):]
			break
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(strings.ToLower(s), "[]")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return "", false
		}
		return v4.String(), true
	}
	if !validDomain(s) {
		return "", false
	}
	return s, true
}

func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-' && i > 0 && i < len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}

func readCatalog(bag map[string]any) []entry {
	var out []entry
	out = append(out, readList("servers", bag["servers"])...)
	out = append(out, readList("stream_servers", bag["stream_servers"])...)
	return out
}

func readList(source string, value any) []entry {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []entry
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(asString(obj["domain"])))
		if !strings.Contains(domain, ".") {
			continue
		}
		fields := map[string]string{"source": source}
		for k, v := range obj {
			fields[k] = asString(v)
		}
		var healthy *bool
		if b, ok := obj["is_healthy"].(bool); ok {
			healthy = &b
		}
		name := strings.TrimSpace(asString(obj["name"]))
		if name == "" {
			name = domain
		}
		out = append(out, entry{
			Source:      source,
			Domain:      domain,
			Name:        name,
			Description: asString(obj["description"]),
			Region:      asString(obj["region"]),
			Country:     asString(obj["country_code"]),
			Flag:        firstNonEmpty(asString(obj["flag_https_1x"]), asString(obj["flag_http_1x"])),
			Latitude:    asString(obj["latitude"]),
			Longitude:   asString(obj["longitude"]),
			Healthy:     healthy,
			Fields:      fields,
		})
	}
	return out
}

// readSavedCatalog reads the catalog archive this tool stores in its own output
// (an array of entries with flat or nested fields). Like a raw catalog, this
// input can run phase 1 and phase 2.
func readSavedCatalog(value any) []entry {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []entry
	seen := map[string]bool{}
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(asString(obj["domain"])))
		if !strings.Contains(domain, ".") || seen[domain] {
			continue
		}
		seen[domain] = true
		fields := map[string]string{}
		if nested, ok := obj["fields"].(map[string]any); ok {
			for k, v := range nested {
				fields[k] = asString(v)
			}
		}
		for k, v := range obj {
			if k == "fields" {
				continue
			}
			if _, exists := fields[k]; !exists {
				fields[k] = asString(v)
			}
		}
		name := strings.TrimSpace(asString(obj["name"]))
		if name == "" {
			name = domain
		}
		var healthy *bool
		if b, ok := obj["healthy"].(bool); ok {
			healthy = &b
		} else if s := fields["is_healthy"]; s != "" {
			b := strings.EqualFold(s, "true")
			healthy = &b
		}
		out = append(out, entry{
			Source:      firstNonEmpty(asString(obj["source"]), fields["source"]),
			Domain:      domain,
			Name:        name,
			Description: firstNonEmpty(asString(obj["description"]), fields["description"]),
			Region:      firstNonEmpty(asString(obj["region"]), fields["region"]),
			Country:     firstNonEmpty(asString(obj["country_code"]), asString(obj["countryCode"]), fields["country_code"]),
			Flag:        firstNonEmpty(asString(obj["flag"]), fields["flag_https_1x"], fields["flag_http_1x"]),
			Latitude:    firstNonEmpty(asString(obj["latitude"]), fields["latitude"]),
			Longitude:   firstNonEmpty(asString(obj["longitude"]), fields["longitude"]),
			Healthy:     healthy,
			Fields:      fields,
		})
	}
	return out
}

func uniqueDomains(entries []entry) []entry {
	seen := map[string]bool{}
	var out []entry
	for _, item := range entries {
		if item.Healthy != nil && !*item.Healthy {
			continue
		}
		if seen[item.Domain] {
			continue
		}
		seen[item.Domain] = true
		out = append(out, item)
	}
	return out
}

func discover(domains []entry, dnsAddr string, conc int, allowPoison bool) []resolved {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
	var done atomic.Int64
	total := len(domains)
	return parallel(domains, conc, func(item entry) resolved {
		row := resolved{entry: item}
		if ip, ok := literalIPv4(item.Domain); ok {
			addr := netip.MustParseAddr(ip)
			if poisonedAddr(addr) {
				row.Poisoned = append(row.Poisoned, ip)
				if allowPoison {
					row.IPs = append(row.IPs, ip)
				}
			} else {
				row.IPs = append(row.IPs, ip)
			}
			n := done.Add(1)
			progress("🔍", n, int64(total))
			return row
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ips, err := resolver.LookupNetIP(ctx, "ip4", item.Domain)
		cancel()
		if err != nil {
			row.Err = err.Error()
		} else {
			seen := map[string]bool{}
			for _, ip := range ips {
				s := ip.String()
				if seen[s] {
					continue
				}
				seen[s] = true
				if poisonedAddr(ip) {
					row.Poisoned = append(row.Poisoned, s)
					if allowPoison {
						row.IPs = append(row.IPs, s)
					}
				} else {
					row.IPs = append(row.IPs, s)
				}
			}
		}
		n := done.Add(1)
		progress("🔍", n, int64(total))
		return row
	})
}

func targetsFrom(rows []resolved) []probe {
	var out []probe
	seen := map[string]bool{}
	for _, row := range rows {
		for _, ip := range row.IPs {
			key := row.Domain + "|" + ip
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, probe{
				Name:        row.Name,
				Domain:      row.Domain,
				IP:          ip,
				Region:      row.Region,
				Description: row.Description,
				Country:     row.Country,
				Flag:        row.Flag,
				Fields:      row.Fields,
			})
		}
	}
	return out
}

func scan(items []probe, conc int, ikeUser, remoteID string, ikeTimeout, tcpTimeout time.Duration) []probe {
	var done atomic.Int64
	total := len(items)
	prime, _ := new(big.Int).SetString(modp2048, 16)
	warmIKE(prime, 32)
	return parallel(items, conc, func(item probe) probe {
		type sample struct {
			ms int
			ok bool
		}
		var tcp443, tcp80 sample
		var ikeRes ikeResult
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			if d, ok := tcpRTT(item.IP, 443, tcpTimeout); ok {
				tcp443 = sample{ms: int(d.Milliseconds()), ok: true}
			}
		}()
		go func() {
			defer wg.Done()
			if d, ok := tcpRTT(item.IP, 80, tcpTimeout); ok {
				tcp80 = sample{ms: int(d.Milliseconds()), ok: true}
			}
		}()
		go func() {
			defer wg.Done()
			ikeRes = probeIKE(item.IP, prime, ikeUser, remoteID, ikeTimeout)
		}()
		wg.Wait()
		var samples []int
		if tcp443.ok {
			samples = append(samples, tcp443.ms)
		}
		if tcp80.ok {
			samples = append(samples, tcp80.ms)
		}
		if len(samples) > 0 {
			minV, maxV, sum := samples[0], samples[0], 0
			for _, n := range samples {
				if n < minV {
					minV = n
				}
				if n > maxV {
					maxV = n
				}
				sum += n
			}
			avg := sum / len(samples)
			item.MinMS = &minV
			item.MaxMS = &maxV
			item.AvgMS = &avg
			item.Reachable = true
		}
		item.Phase1 = ikeRes.Phase1
		item.Phase2 = ikeRes.Phase2
		item.AuthStatus = ikeRes.AuthStatus
		if ikeRes.OK {
			item.IKEv2 = true
			port := ikeRes.Port
			item.IKEPort = &port
			ms := int(ikeRes.RTT.Milliseconds())
			item.IKEMS = &ms
		}
		n := done.Add(1)
		progress("📡", n, int64(total))
		return item
	})
}

func probesFromMaps(list []map[string]any) []probe {
	var out []probe
	for _, obj := range list {
		out = append(out, probeFromMap(obj)...)
	}
	return out
}

func probesFromAny(list []any) []probe {
	var out []probe
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, probeFromMap(obj)...)
	}
	return out
}

func probeFromMap(obj map[string]any) []probe {
	name := asString(obj["name"])
	domain := asString(obj["domain"])
	if domain == "" {
		domain = name
	}
	fields := map[string]string{}
	if raw, ok := obj["fields"].(map[string]any); ok {
		for k, v := range raw {
			fields[k] = asString(v)
		}
	}
	base := probe{
		Name:        name,
		Domain:      domain,
		Region:      asString(obj["region"]),
		Description: asString(obj["description"]),
		Country:     asString(obj["country_code"]),
		Flag:        asString(obj["flag"]),
		Phase1:      asString(obj["phase1"]),
		Phase2:      asString(obj["phase2"]),
		AuthStatus:  asString(obj["auth_status"]),
		Fields:      fields,
	}
	if ips, ok := obj["ips"].([]any); ok {
		var out []probe
		for _, ip := range ips {
			s := asString(ip)
			if net.ParseIP(s) == nil || poisoned(net.ParseIP(s)) {
				continue
			}
			row := base
			row.IP = s
			out = append(out, row)
		}
		return out
	}
	ip := asString(obj["ip"])
	if net.ParseIP(ip) == nil || poisoned(net.ParseIP(ip)) {
		return nil
	}
	base.IP = ip
	return []probe{base}
}

func writeAll(jsonPath, xlsxPath, csvPath string, entries []entry, probes []probe, found []resolved) {
	rows := exportRows(entries, probes, found)
	payload := map[string]any{
		"discovery": found,
		"probes":    probes,
		"rows":      rows,
	}
	blob, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ could not build JSON: %v\n", err)
	} else if err := os.WriteFile(jsonPath, blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "❌ could not write JSON (%s): %v\n", jsonPath, err)
	} else {
		fmt.Fprintf(os.Stderr, "📄 JSON: %s\n", jsonPath)
	}
	if err := writeCSV(csvPath, columns(rows), rows); err != nil {
		fmt.Fprintf(os.Stderr, "❌ could not write CSV (%s): %v\n", csvPath, err)
	} else {
		fmt.Fprintf(os.Stderr, "📄 CSV: %s\n", csvPath)
	}
	if err := writeXLSX(xlsxPath, columns(rows), rows); err != nil {
		fmt.Fprintf(os.Stderr, "❌ could not write Excel (%s): %v\n", xlsxPath, err)
	} else {
		fmt.Fprintf(os.Stderr, "📊 Excel: %s\n", xlsxPath)
	}
}

func exportRows(entries []entry, probes []probe, found []resolved) []map[string]string {
	byDomain := map[string][]probe{}
	for _, item := range probes {
		byDomain[item.Domain] = append(byDomain[item.Domain], item)
	}
	ipsByDomain := map[string]resolved{}
	for _, row := range found {
		ipsByDomain[row.Domain] = row
	}
	var rows []map[string]string
	seen := map[string]bool{}
	push := func(fields map[string]string, item *probe, ips []string, poisonedIPs []string, errText string) {
		row := map[string]string{}
		for k, v := range fields {
			row[k] = v
		}
		if len(ips) > 0 {
			row["ips"] = strings.Join(ips, " ")
		}
		if len(poisonedIPs) > 0 {
			row["poisoned_ips"] = strings.Join(poisonedIPs, " ")
		}
		if errText != "" {
			row["dns_error"] = errText
		}
		if item != nil {
			row["ip"] = item.IP
			row["min_ms"] = num(item.MinMS)
			row["avg_ms"] = num(item.AvgMS)
			row["max_ms"] = num(item.MaxMS)
			row["reachable"] = yes(item.Reachable)
			row["ikev2"] = yes(item.IKEv2)
			row["phase1"] = item.Phase1
			row["phase2"] = item.Phase2
			row["auth_status"] = item.AuthStatus
			row["ike_port"] = num(item.IKEPort)
			row["ike_ms"] = num(item.IKEMS)
		}
		rows = append(rows, row)
	}
	if len(entries) == 0 {
		for i := range probes {
			push(probeMeta(&probes[i]), &probes[i], nil, nil, "")
		}
		return rows
	}
	for _, item := range entries {
		seen[item.Domain] = true
		disc, ok := ipsByDomain[item.Domain]
		list := byDomain[item.Domain]
		if len(list) == 0 {
			var ips, poisonedIPs []string
			errText := ""
			if ok {
				ips, poisonedIPs, errText = disc.IPs, disc.Poisoned, disc.Err
			}
			push(item.Fields, nil, ips, poisonedIPs, errText)
			continue
		}
		for i := range list {
			push(item.Fields, &list[i], nil, nil, "")
		}
	}
	for domain, list := range byDomain {
		if seen[domain] {
			continue
		}
		for i := range list {
			push(probeMeta(&list[i]), &list[i], nil, nil, "")
		}
	}
	return rows
}

// probeMeta copies the main catalog fields off the probe so name, country, and
// region columns stay filled when the input file is only probe results.
func probeMeta(item *probe) map[string]string {
	fields := map[string]string{}
	for k, v := range item.Fields {
		fields[k] = v
	}
	if fields["name"] == "" {
		fields["name"] = item.Name
	}
	if fields["domain"] == "" {
		fields["domain"] = item.Domain
	}
	if fields["country_code"] == "" && item.Country != "" {
		fields["country_code"] = item.Country
	}
	if fields["region"] == "" && item.Region != "" {
		fields["region"] = item.Region
	}
	return fields
}

func writeCSV(path string, cols []string, rows []map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.Write(cols); err != nil {
		return err
	}
	for _, row := range rows {
		rec := make([]string, len(cols))
		for i, col := range cols {
			rec[i] = row[col]
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func columns(rows []map[string]string) []string {
	preferred := []string{
		"source", "name", "description", "region", "country_code", "domain", "ip", "ips",
		"min_ms", "avg_ms", "max_ms", "reachable", "ikev2", "phase1", "phase2", "auth_status",
		"ike_port", "ike_ms", "poisoned_ips", "dns_error",
	}
	seen := map[string]bool{}
	var cols []string
	for _, col := range preferred {
		for _, row := range rows {
			if _, ok := row[col]; ok {
				cols = append(cols, col)
				seen[col] = true
				break
			}
		}
	}
	extra := map[string]bool{}
	for _, row := range rows {
		for key := range row {
			if !seen[key] {
				extra[key] = true
			}
		}
	}
	var rest []string
	for key := range extra {
		rest = append(rest, key)
	}
	sort.Strings(rest)
	return append(cols, rest...)
}

func summarize(probes []probe) {
	p2Good, p1Only, dead := 0, 0, 0
	var best *probe
	for i := range probes {
		item := &probes[i]
		if item.Phase2 == statusOK {
			p2Good++
			if best == nil || (item.AvgMS != nil && best.AvgMS != nil && *item.AvgMS < *best.AvgMS) {
				best = item
			}
		} else if item.Phase1 == statusOK {
			p1Only++
		} else {
			dead++
		}
	}
	fmt.Fprintf(os.Stderr, "✅ phase 1 and 2 verified: %d | ⚠️ phase 1 only: %d | ❌ failed: %d\n", p2Good, p1Only, dead)
	if best != nil {
		ikePort := 0
		if best.IKEPort != nil {
			ikePort = *best.IKEPort
		}
		avgMS := 0
		if best.AvgMS != nil {
			avgMS = *best.AvgMS
		}
		fmt.Fprintf(os.Stderr, "🏆 best real server: %s  %s  %dms  IKEv2:%d (%s)\n", best.IP, best.Name, avgMS, ikePort, best.AuthStatus)
	}
}

var progressMu sync.Mutex

func progress(label string, n, total int64) {
	progressMu.Lock()
	fmt.Fprintf(os.Stderr, "\r%s %d/%d", label, n, total)
	if n == total {
		fmt.Fprintln(os.Stderr)
	}
	progressMu.Unlock()
}

func parallel[T any, R any](items []T, n int, fn func(T) R) []R {
	if len(items) == 0 {
		return nil
	}
	if n < 1 {
		n = 1
	}
	if n > len(items) {
		n = len(items)
	}
	out := make([]R, len(items))
	var idx atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(idx.Add(1) - 1)
				if i >= len(items) {
					return
				}
				out[i] = fn(items[i])
			}
		}()
	}
	wg.Wait()
	return out
}

func literalIPv4(host string) (string, bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return "", false
	}
	return ip.String(), true
}

func poisonedAddr(ip netip.Addr) bool {
	if !ip.Is4() {
		return true
	}
	b := ip.As4()
	return poisoned(net.IP(b[:]))
}

func poisoned(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return true
	}
	a, b := v4[0], v4[1]
	switch {
	case a == 10 || a == 127 || a == 0:
		return true
	case a == 192 && b == 168:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 100 && b >= 64 && b <= 127:
		return true
	case a == 169 && b == 254:
		return true
	default:
		return false
	}
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == math.Trunc(t) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func num(v *int) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(*v)
}

func yes(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
