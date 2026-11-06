package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Entry struct {
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

type Resolved struct {
	Entry
	IPs      []string `json:"ips"`
	Poisoned []string `json:"poisoned,omitempty"`
	Err      string   `json:"error,omitempty"`
}

type Probe struct {
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

func LoadInput(path string) ([]Entry, []Probe, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", err
	}
	return ParseInputContent(string(raw))
}

func ParseInputContent(content string) ([]Entry, []Probe, string, error) {
	trim := strings.TrimSpace(strings.TrimPrefix(content, "\uFEFF"))
	if trim == "" {
		return nil, nil, "", fmt.Errorf("content is empty")
	}
	if !strings.HasPrefix(trim, "{") && !strings.HasPrefix(trim, "[") {
		entries := ReadHostList(trim)
		if len(entries) == 0 {
			return nil, nil, "", fmt.Errorf("no valid domain found in the text")
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
		return ReadCatalog(bag), nil, "catalog", nil
	}
	if catalog, ok := bag["catalog"]; ok {
		if entries := ReadSavedCatalog(catalog); len(entries) > 0 {
			return entries, nil, "catalog", nil
		}
	}
	type stored struct {
		Probes    []Probe    `json:"probes"`
		Discovery []Resolved `json:"discovery"`
	}
	var doc stored
	if err := json.Unmarshal([]byte(trim), &doc); err != nil {
		return nil, nil, "", err
	}
	if len(doc.Probes) > 0 {
		return nil, doc.Probes, "results", nil
	}
	if len(doc.Discovery) > 0 {
		return nil, TargetsFrom(doc.Discovery), "results", nil
	}
	if rows, ok := bag["rows"].([]any); ok {
		return nil, probesFromAny(rows), "results", nil
	}
	return nil, nil, "", fmt.Errorf("unrecognized format")
}

func ReadHostList(text string) []Entry {
	var out []Entry
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
			host, ok := NormalizeHost(token)
			if !ok || seen[host] {
				continue
			}
			seen[host] = true
			out = append(out, Entry{
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

func NormalizeHost(raw string) (string, bool) {
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
	if !ValidDomain(s) {
		return "", false
	}
	return s, true
}

func ValidDomain(s string) bool {
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

func ReadCatalog(bag map[string]any) []Entry {
	var out []Entry
	out = append(out, ReadList("servers", bag["servers"])...)
	out = append(out, ReadList("stream_servers", bag["stream_servers"])...)
	return out
}

func ReadList(source string, value any) []Entry {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []Entry
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
		out = append(out, Entry{
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

func ReadSavedCatalog(value any) []Entry {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []Entry
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
		out = append(out, Entry{
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

func UniqueDomains(entries []Entry) []Entry {
	seen := map[string]bool{}
	var out []Entry
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

func Discover(domains []Entry, dnsAddr string, conc int, allowPoison bool) []Resolved {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
	var done atomic.Int64
	total := len(domains)
	return parallel(domains, conc, func(item Entry) Resolved {
		row := Resolved{Entry: item}
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

func TargetsFrom(rows []Resolved) []Probe {
	var out []Probe
	seen := map[string]bool{}
	for _, row := range rows {
		for _, ip := range row.IPs {
			key := row.Domain + "|" + ip
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Probe{
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

func Scan(items []Probe, conc int, ikeUser, remoteID string, ikeTimeout, tcpTimeout time.Duration) []Probe {
	var done atomic.Int64
	total := len(items)
	prime, _ := new(big.Int).SetString(modp2048, 16)
	warmIKE(prime, 32)
	return parallel(items, conc, func(item Probe) Probe {
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

func probesFromMaps(list []map[string]any) []Probe {
	var out []Probe
	for _, obj := range list {
		out = append(out, probeFromMap(obj)...)
	}
	return out
}

func probesFromAny(list []any) []Probe {
	var out []Probe
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, probeFromMap(obj)...)
	}
	return out
}

func probeFromMap(obj map[string]any) []Probe {
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
	base := Probe{
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
		var out []Probe
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
	return []Probe{base}
}

func WriteAll(jsonPath, xlsxPath, csvPath string, entries []Entry, probes []Probe, found []Resolved) {
	rows := ExportRows(entries, probes, found)
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

func ExportRows(entries []Entry, probes []Probe, found []Resolved) []map[string]string {
	byDomain := map[string][]Probe{}
	for _, item := range probes {
		byDomain[item.Domain] = append(byDomain[item.Domain], item)
	}
	ipsByDomain := map[string]Resolved{}
	for _, row := range found {
		ipsByDomain[row.Domain] = row
	}
	var rows []map[string]string
	seen := map[string]bool{}
	push := func(fields map[string]string, item *Probe, ips []string, poisonedIPs []string, errText string) {
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
			push(ProbeMeta(&probes[i]), &probes[i], nil, nil, "")
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
			push(ProbeMeta(&list[i]), &list[i], nil, nil, "")
		}
	}
	return rows
}

func ProbeMeta(item *Probe) map[string]string {
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

func Summarize(probes []Probe) {
	p2Good, p1Only, dead := 0, 0, 0
	var best *Probe
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

// Backward compatibility aliases for internal engine tests
type entry = Entry
type resolved = Resolved
type probe = Probe

func loadInput(path string) ([]Entry, []Probe, string, error) {
	return LoadInput(path)
}
func readHostList(text string) []Entry {
	return ReadHostList(text)
}
func normalizeHost(raw string) (string, bool) {
	return NormalizeHost(raw)
}
func validDomain(s string) bool {
	return ValidDomain(s)
}
func readCatalog(bag map[string]any) []Entry {
	return ReadCatalog(bag)
}
func readSavedCatalog(value any) []Entry {
	return ReadSavedCatalog(value)
}
func uniqueDomains(entries []Entry) []Entry {
	return UniqueDomains(entries)
}
func discover(domains []Entry, dnsAddr string, conc int, allowPoison bool) []Resolved {
	return Discover(domains, dnsAddr, conc, allowPoison)
}
func targetsFrom(rows []Resolved) []Probe {
	return TargetsFrom(rows)
}
func scan(items []Probe, conc int, ikeUser, remoteID string, ikeTimeout, tcpTimeout time.Duration) []Probe {
	return Scan(items, conc, ikeUser, remoteID, ikeTimeout, tcpTimeout)
}
func writeAll(jsonPath, xlsxPath, csvPath string, entries []Entry, probes []Probe, found []Resolved) {
	WriteAll(jsonPath, xlsxPath, csvPath, entries, probes, found)
}
func exportRows(entries []Entry, probes []Probe, found []Resolved) []map[string]string {
	return ExportRows(entries, probes, found)
}
func probeMeta(item *Probe) map[string]string {
	return ProbeMeta(item)
}
func summarize(probes []Probe) {
	Summarize(probes)
}
