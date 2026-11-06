package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nordAPI      = "https://api.nordvpn.com/v1/servers"
	nordPage     = 1000
	nordWorkers  = 8
	cacheVersion = 1
)

type nordOpts struct {
	refresh    bool
	ttl        time.Duration
	limit      int
	conc       int
	country    string
	maxLoad    int
	offline    bool
	proto      string
	scan       scanProtos
	ikeTimeout time.Duration
	tcpTimeout time.Duration
	ikeUser    string
	ikeID      string
	jsonPath   string
	csvPath    string
	xlsxPath   string
	saw        map[string]bool
}

func (o *nordOpts) seen(name string) {
	if o.saw == nil {
		o.saw = map[string]bool{}
	}
	o.saw[name] = true
}

type nordServer struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	IP       string   `json:"ip"`
	Load     int      `json:"load"`
	Status   string   `json:"status"`
	Code     string   `json:"country_code"`
	Country  string   `json:"country"`
	City     string   `json:"city"`
	Groups   []string `json:"identifier"`
	Services []string `json:"services"`
	Tech     []string `json:"technologies"`
	WGPub    string   `json:"wg_public_key,omitempty"`
	Version  string   `json:"version,omitempty"`
}

type nordHit struct {
	Server     nordServer
	HasWG      bool
	HasOUDP    bool
	HasOTCP    bool
	HasIKE     bool
	WG         string
	WGDetail   string
	WGMS       int
	OUDP       string
	OUDPDetail string
	OUDPMS     int
	OTCP       string
	OTCPDetail string
	OTCPMS     int
	U53        string
	U53Detail  string
	U53MS      int
	T80        string
	T80Detail  string
	T80MS      int
	IKE        string
	IKEPhase1  string
	IKEPhase2  string
	IKEAuth    string
	IKEPort    int
	IKEMS      int
	Fresh      string
	Firewall   string
}

func runNord(o nordOpts) error {
	// 128 in-flight handshakes drew no replies at all. 32 verified every server in a sample.
	if !o.saw["c"] {
		o.conc = 32
	}
	if o.conc < 1 {
		o.conc = 1
	}
	if !o.saw["ike-timeout"] {
		o.ikeTimeout = 1000 * time.Millisecond
	}
	if !o.saw["tcp-timeout"] {
		o.tcpTimeout = 1000 * time.Millisecond
	}
	if !o.saw["ike-user"] {
		o.ikeUser = "health@nordvpn.com"
	}
	if !o.saw["ike-id"] {
		o.ikeID = "nordvpn.com"
	}
	if !o.saw["json"] {
		o.jsonPath = "nord-results.json"
	}
	if !o.saw["csv"] {
		o.csvPath = "nord-results.csv"
	}
	if !o.saw["xlsx"] {
		o.xlsxPath = "nord-results.xlsx"
	}
	if o.maxLoad < 0 || o.maxLoad > 100 {
		return errors.New("-load must be between 0 and 100")
	}
	if strings.TrimSpace(o.proto) == "" {
		o.proto = "ikev2"
	}
	scan, err := parseScanProtos(o.proto)
	if err != nil {
		return err
	}
	o.scan = scan

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	list, source, fetched, err := loadNord(ctx, o.refresh, o.ttl)
	if err != nil {
		return err
	}
	countries := splitComma(o.country)
	filtered := list[:0:0]
	for _, s := range list {
		if !o.offline && !strings.EqualFold(s.Status, "online") {
			continue
		}
		if s.Load > o.maxLoad || !countryOK(s, countries) {
			continue
		}
		if !o.scan.match(s) {
			continue
		}
		if net.ParseIP(s.IP) == nil || poisoned(net.ParseIP(s.IP)) {
			continue
		}
		filtered = append(filtered, s)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Load != filtered[j].Load {
			return filtered[i].Load < filtered[j].Load
		}
		return filtered[i].Hostname < filtered[j].Hostname
	})
	if o.limit > 0 && len(filtered) > o.limit {
		filtered = filtered[:o.limit]
	}
	fmt.Fprintf(os.Stderr, "nord: %d servers from %s (%s), probing %d (%s), workers %d\n",
		len(list), source, fetched.Format(time.RFC3339), len(filtered), o.scan.label(), o.conc)
	fmt.Fprintln(os.Stderr, o.scan.portLine())

	prime, _ := new(big.Int).SetString(modp2048, 16)
	if o.scan.onIKE() {
		warmIKE(prime, 32)
	}
	var pool *udpPool
	if o.scan.needsUDP() {
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

	done := 0
	var mu sync.Mutex
	hits := parallel(filtered, o.conc, func(s nordServer) nordHit {
		h := probeServer(ctx, pool, prime, s, o)
		mu.Lock()
		done++
		if done%64 == 0 || done == len(filtered) {
			progress("nord", int64(done), int64(len(filtered)))
		}
		mu.Unlock()
		return h
	})
	if o.scan.onIKE() {
		hits = retryIKE(ctx, prime, hits, o)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		ri, rj := freshRank(hits[i].Fresh, hits[i].Firewall), freshRank(hits[j].Fresh, hits[j].Firewall)
		if ri != rj {
			return ri < rj
		}
		if hits[i].Server.Load != hits[j].Server.Load {
			return hits[i].Server.Load < hits[j].Server.Load
		}
		if a, b := hits[i].rtt(), hits[j].rtt(); a != b {
			return a < b
		}
		return hits[i].Server.Hostname < hits[j].Server.Hostname
	})
	rows, cols := flattenNord(hits)
	if err := writeNord(o.jsonPath, o.csvPath, o.xlsxPath, source, fetched, rows, cols); err != nil {
		return err
	}
	summarizeNord(hits)
	return nil
}

func retryIKE(ctx context.Context, prime *big.Int, hits []nordHit, o nordOpts) []nordHit {
	var idx []int
	for i := range hits {
		if hits[i].HasIKE && (hits[i].IKE == "silent" || hits[i].IKE == "unproven") {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 || ctx.Err() != nil {
		return hits
	}
	fmt.Fprintf(os.Stderr, "retry IKEv2 on %d silent servers\n", len(idx))
	conc := o.conc / 2
	if conc < 8 {
		conc = 8
	}
	if conc > 16 {
		conc = 16
	}
	parallel(idx, conc, func(i int) int {
		if ctx.Err() != nil {
			return 0
		}
		res := probeIKE(hits[i].Server.IP, prime, o.ikeUser, o.ikeID, o.ikeTimeout)
		st := normIKE(res)
		if st == "silent" || st == "unproven" || st == "" {
			return 0
		}
		hits[i].IKE = st
		hits[i].IKEPhase1 = res.Phase1
		hits[i].IKEPhase2 = res.Phase2
		hits[i].IKEAuth = res.AuthStatus
		hits[i].IKEPort = res.Port
		if res.RTT > 0 {
			hits[i].IKEMS = int(res.RTT.Milliseconds())
		}
		hits[i].Fresh, hits[i].Firewall = scoreHit(hits[i])
		return 1
	})
	return hits
}

func probeServer(ctx context.Context, pool *udpPool, prime *big.Int, s nordServer, o nordOpts) nordHit {
	h := nordHit{
		Server: s,
		WG:     "skip", OUDP: "skip", OTCP: "skip", IKE: "skip",
		U53: "skip", T80: "skip",
		WGMS: -1, OUDPMS: -1, OTCPMS: -1, U53MS: -1, T80MS: -1, IKEMS: -1,
	}
	h.HasWG = hasTech(s.Tech, "wireguard_udp")
	h.HasOUDP = hasTech(s.Tech, "openvpn_udp")
	h.HasOTCP = hasTech(s.Tech, "openvpn_tcp")
	h.HasIKE = hasTech(s.Tech, "ikev2")
	if ctx.Err() != nil {
		h.Fresh, h.Firewall = "skip", "interrupted"
		return h
	}
	var (
		wgSt, wgDetail, ou, ouD, ot, otD, u53, u53d, t80, t80d string
		wgMS, ouMS, otMS, u53MS, t80MS                         = -1, -1, -1, -1, -1
		ikeSt, p1, p2, auth                                    string
		ikePort, ikeMS                                         = 0, -1
		wg                                                     sync.WaitGroup
	)
	if h.HasWG && o.scan.onWG() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wgSt, wgDetail, wgMS = probeWG(ctx, pool, s.IP, s.WGPub, o.ikeTimeout)
		}()
	}
	if h.HasOUDP && o.scan.onOUDP() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ou, ouD, ouMS = probeOVPNUDP(ctx, pool, s.IP, portOUDP, o.ikeTimeout)
		}()
	}
	if h.HasOTCP && o.scan.onOTCP() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ot, otD, otMS = probeOVPNTCP(ctx, s.IP, portOTCP, o.tcpTimeout)
		}()
	}
	if o.scan.full {
		wg.Add(2)
		go func() {
			defer wg.Done()
			u53, u53d, u53MS = probeOVPNUDP(ctx, pool, s.IP, portDNS, o.ikeTimeout)
		}()
		go func() {
			defer wg.Done()
			t80, t80d, t80MS = probeOVPNTCP(ctx, s.IP, portHTTP, o.tcpTimeout)
		}()
	}
	if h.HasIKE && o.scan.onIKE() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := probeIKE(s.IP, prime, o.ikeUser, o.ikeID, o.ikeTimeout)
			ikeSt = normIKE(res)
			p1, p2, auth = res.Phase1, res.Phase2, res.AuthStatus
			ikePort = res.Port
			if res.RTT > 0 {
				ikeMS = int(res.RTT.Milliseconds())
			}
		}()
	}
	wg.Wait()
	h.WG, h.WGDetail, h.WGMS = wgSt, wgDetail, wgMS
	h.OUDP, h.OUDPDetail, h.OUDPMS = ou, ouD, ouMS
	h.OTCP, h.OTCPDetail, h.OTCPMS = ot, otD, otMS
	h.U53, h.U53Detail, h.U53MS = u53, u53d, u53MS
	h.T80, h.T80Detail, h.T80MS = t80, t80d, t80MS
	h.IKE, h.IKEPhase1, h.IKEPhase2, h.IKEAuth = ikeSt, p1, p2, auth
	h.IKEPort, h.IKEMS = ikePort, ikeMS
	if h.WG == "" {
		h.WG = "skip"
	}
	h.Fresh, h.Firewall = scoreHit(h)
	return h
}

func probeWG(ctx context.Context, pool *udpPool, ip, pubB64 string, timeout time.Duration) (string, string, int) {
	pub, err := decodeWGKey(pubB64)
	if err != nil {
		return "skip", "no wireguard key", -1
	}
	mac1Key, cookieKey := wgMACKeys(pub)
	good, goodSender, mac1 := buildWG(&mac1Key, true)
	bad, badSender, _ := buildWG(nil, false)
	if badSender == goodSender {
		badSender++
		binaryPut32(bad[4:8], badSender)
	}
	start := time.Now()
	got, err := pool.collect(ctx, ip, portWG, [][]byte{good, bad}, timeout, func(pkts [][]byte) bool {
		st, _ := judgeWG(pkts, goodSender, badSender, mac1, cookieKey[:])
		return st == "fake"
	})
	if len(got) == 0 {
		if err != nil {
			return "silent", err.Error(), -1
		}
		return "silent", "no reply", -1
	}
	st, detail := judgeWG(got, goodSender, badSender, mac1, cookieKey[:])
	return st, detail, int(time.Since(start).Milliseconds())
}

func probeOVPNUDP(ctx context.Context, pool *udpPool, ip string, port int, timeout time.Duration) (string, string, int) {
	pkt, sid := ovpnHardReset()
	start := time.Now()
	got, err := pool.collect(ctx, ip, port, [][]byte{pkt}, timeout, func(pkts [][]byte) bool {
		return len(pkts) > 0
	})
	if len(got) == 0 {
		if err != nil {
			return "silent", err.Error(), -1
		}
		return "silent", "no reply", -1
	}
	st, detail := judgeOVPN(got[0], sid, false, port)
	return st, detail, int(time.Since(start).Milliseconds())
}

func binaryPut32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func normIKE(r ikeResult) string {
	if r.Phase1 == statusOK && r.Phase2 == statusOK {
		return "real"
	}
	if r.Phase1 == statusOK {
		return "p1"
	}
	switch r.Phase1 {
	case "", statusNoReply:
		return "silent"
	case statusConnectErr, statusSendErr:
		// A UDP dial failure here is local (socket limit, route), not a refused server.
		return "unproven"
	case statusIncomplete:
		return "unproven"
	default:
		return "fake"
	}
}

func scoreHit(h nordHit) (fresh, firewall string) {
	fake, intercept, blocked, real, p1 := false, false, false, false, false
	note := func(st string, need bool) {
		switch st {
		case "real":
			real = true
		case "p1":
			p1 = true
		case "fake":
			fake = true
		case "other":
			if need {
				intercept = true
			}
		case "closed":
			if need {
				blocked = true
			}
		}
	}
	if h.HasWG {
		note(h.WG, false)
	}
	if h.HasOUDP {
		note(h.OUDP, true)
	}
	if h.HasOTCP {
		note(h.OTCP, true)
	}
	if h.HasIKE {
		note(h.IKE, true)
	}
	note(h.U53, false)
	note(h.T80, false)
	switch {
	case fake:
		return "no", "inject"
	case intercept:
		return "no", "intercept"
	case blocked:
		return "no", "blocked"
	case real:
		return "yes", "clean"
	case p1:
		return "yes", "phase1"
	default:
		return "unproven", "no-reply"
	}
}

func freshRank(fresh, firewall string) int {
	switch {
	case fresh == "yes" && firewall == "clean":
		return 0
	case fresh == "yes":
		return 1
	case fresh == "unproven":
		return 2
	case fresh == "skip":
		return 4
	default:
		return 3
	}
}

func (h nordHit) rtt() int {
	best := -1
	consider := func(st string, n int) {
		if (st == "real" || st == "p1") && n >= 0 && (best < 0 || n < best) {
			best = n
		}
	}
	consider(h.WG, h.WGMS)
	consider(h.OUDP, h.OUDPMS)
	consider(h.OTCP, h.OTCPMS)
	consider(h.IKE, h.IKEMS)
	if best < 0 {
		return 1 << 30
	}
	return best
}

func hasTech(list []string, id string) bool {
	return slices.Contains(list, id)
}

var nordCols = []string{
	"fresh", "firewall", "proven", "name", "id", "identifier", "hostname", "ip",
	"load", "status", "country_code", "country", "city",
	"services", "technologies", "wg_public_key", "version",
	"wg", "wg_detail", "wg_ms",
	"ovpn_udp", "ovpn_udp_detail", "ovpn_udp_ms",
	"ovpn_tcp", "ovpn_tcp_detail", "ovpn_tcp_ms",
	"ovpn_udp53", "ovpn_udp53_detail", "ovpn_udp53_ms",
	"ovpn_tcp80", "ovpn_tcp80_detail", "ovpn_tcp80_ms",
	"ike", "ike_port", "ike_phase1", "ike_phase2", "ike_auth", "ike_ms",
	"rtt_ms",
}

func flattenNord(hits []nordHit) ([]map[string]string, []string) {
	svcSet := map[string]struct{}{}
	for _, h := range hits {
		for _, s := range h.Server.Services {
			svcSet[s] = struct{}{}
		}
	}
	svcCols := make([]string, 0, len(svcSet))
	for s := range svcSet {
		svcCols = append(svcCols, "svc_"+s)
	}
	sort.Strings(svcCols)
	cols := append(append([]string{}, nordCols...), svcCols...)
	rows := make([]map[string]string, 0, len(hits))
	for _, h := range hits {
		s := h.Server
		row := map[string]string{
			"fresh": h.Fresh, "firewall": h.Firewall, "proven": provenOf(h),
			"name": s.Name, "id": strconv.Itoa(s.ID),
			"identifier": strings.Join(s.Groups, ","),
			"hostname":   s.Hostname, "ip": s.IP,
			"load": strconv.Itoa(s.Load), "status": s.Status,
			"country_code": s.Code, "country": s.Country, "city": s.City,
			"services":      strings.Join(s.Services, ","),
			"technologies":  strings.Join(s.Tech, ","),
			"wg_public_key": s.WGPub, "version": s.Version,
			"wg": or(h.WG, "skip"), "wg_detail": h.WGDetail, "wg_ms": ms(h.WGMS),
			"ovpn_udp": or(h.OUDP, "skip"), "ovpn_udp_detail": h.OUDPDetail, "ovpn_udp_ms": ms(h.OUDPMS),
			"ovpn_tcp": or(h.OTCP, "skip"), "ovpn_tcp_detail": h.OTCPDetail, "ovpn_tcp_ms": ms(h.OTCPMS),
			"ovpn_udp53": or(h.U53, "skip"), "ovpn_udp53_detail": h.U53Detail, "ovpn_udp53_ms": ms(h.U53MS),
			"ovpn_tcp80": or(h.T80, "skip"), "ovpn_tcp80_detail": h.T80Detail, "ovpn_tcp80_ms": ms(h.T80MS),
			"ike": or(h.IKE, "skip"), "ike_port": portStr(h.IKEPort),
			"ike_phase1": h.IKEPhase1, "ike_phase2": h.IKEPhase2, "ike_auth": h.IKEAuth,
			"ike_ms": ms(h.IKEMS), "rtt_ms": rttCell(h),
		}
		for _, c := range svcCols {
			row[c] = "no"
		}
		for _, id := range s.Services {
			row["svc_"+id] = "yes"
		}
		rows = append(rows, row)
	}
	return rows, cols
}

func provenOf(h nordHit) string {
	var p []string
	if h.IKE == "real" {
		p = append(p, "ike")
	} else if h.IKE == "p1" {
		p = append(p, "ike_phase1")
	}
	if h.WG == "real" {
		p = append(p, "wireguard")
	}
	if h.OUDP == "real" {
		p = append(p, "openvpn_udp")
	}
	if h.OTCP == "real" {
		p = append(p, "openvpn_tcp")
	}
	return strings.Join(p, "+")
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func ms(n int) string {
	if n < 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func rttCell(h nordHit) string {
	n := h.rtt()
	if n >= 1<<30 {
		return ""
	}
	return strconv.Itoa(n)
}

func portStr(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func writeNord(jsonPath, csvPath, xlsxPath, source string, fetched time.Time, rows []map[string]string, cols []string) error {
	fresh := 0
	for _, row := range rows {
		if row["fresh"] == "yes" {
			fresh++
		}
	}
	doc := map[string]any{
		"source":  source,
		"fetched": fetched.UTC().Format(time.RFC3339),
		"count":   len(rows),
		"fresh":   fresh,
		"columns": cols,
		"servers": rows,
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, blob, 0o644); err != nil {
		return err
	}
	if err := writeCSV(csvPath, cols, rows); err != nil {
		return err
	}
	if err := writeXLSX(xlsxPath, cols, rows); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "json %s\ncsv  %s\nxlsx %s\n", jsonPath, csvPath, xlsxPath)
	return nil
}

func summarizeNord(hits []nordHit) {
	var yes, p1, unproven, inject, blocked, other int
	for _, h := range hits {
		switch {
		case h.Fresh == "yes" && h.Firewall == "clean":
			yes++
		case h.Fresh == "yes":
			p1++
		case h.Fresh == "unproven":
			unproven++
		case h.Firewall == "inject":
			inject++
		case h.Firewall == "blocked":
			blocked++
		default:
			other++
		}
	}
	fmt.Fprintf(os.Stderr, "fresh %d verified, %d phase1-only, %d unproven, %d inject, %d blocked, %d other\n",
		yes, p1, unproven, inject, blocked, other)
	n := 0
	for _, h := range hits {
		if h.Fresh != "yes" {
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s  %s  load %d  %s  wg %s  ovpn %s/%s  ike %s %s\n",
			h.Server.Hostname, h.Server.IP, h.Server.Load, h.Firewall,
			h.WG, h.OUDP, h.OTCP, h.IKE, h.IKEAuth)
		n++
		if n == 8 {
			break
		}
	}
}

func loadNord(ctx context.Context, refresh bool, ttl time.Duration) ([]nordServer, string, time.Time, error) {
	path, err := nordCachePath()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if !refresh {
		if list, fetched, ok := readNordCache(path, ttl, time.Now()); ok {
			return list, "cache " + path, fetched, nil
		}
	}
	list, err := fetchNord(ctx)
	if err != nil {
		if list, fetched, ok := readNordCache(path, 365*24*time.Hour, time.Now()); ok {
			fmt.Fprintf(os.Stderr, "download failed (%v); using stale cache\n", err)
			return list, "stale " + path, fetched, nil
		}
		return nil, "", time.Time{}, err
	}
	if err := writeNordCache(path, list); err != nil {
		fmt.Fprintf(os.Stderr, "not caching: %v\n", err)
	}
	return list, "download", time.Now().UTC(), nil
}

func nordCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "nord-full-cache.json", nil
	}
	dir := filepath.Join(home, ".cache", "nordike")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "full-v1.json"), nil
}

type nordCacheFile struct {
	Version int          `json:"version"`
	Fetched time.Time    `json:"fetched"`
	Servers []nordServer `json:"servers"`
}

func readNordCache(path string, ttl time.Duration, now time.Time) ([]nordServer, time.Time, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, false
	}
	defer f.Close()
	var doc nordCacheFile
	if err := json.NewDecoder(f).Decode(&doc); err != nil || doc.Version != cacheVersion {
		return nil, time.Time{}, false
	}
	if doc.Fetched.IsZero() || now.Sub(doc.Fetched) >= ttl || len(doc.Servers) == 0 {
		return nil, time.Time{}, false
	}
	return doc.Servers, doc.Fetched, true
}

func writeNordCache(path string, list []nordServer) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	enc := json.NewEncoder(bw)
	doc := nordCacheFile{Version: cacheVersion, Fetched: time.Now().UTC(), Servers: list}
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return bw.Flush()
}

func fetchNord(ctx context.Context) ([]nordServer, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := nordClient()
	type page struct {
		offset int
		items  []nordServer
		err    error
	}
	jobs := make(chan int, nordWorkers)
	pages := make(chan page, nordWorkers)
	var wg sync.WaitGroup
	for i := 0; i < nordWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for off := range jobs {
				items, err := fetchNordPage(ctx, client, off)
				pages <- page{off, items, err}
			}
		}()
	}
	next, inFlight := 0, 0
	launch := func() {
		jobs <- next
		next += nordPage
		inFlight++
	}
	for i := 0; i < nordWorkers; i++ {
		launch()
	}
	got := map[int][]nordServer{}
	var first error
	stop := false
	for inFlight > 0 {
		p := <-pages
		inFlight--
		if p.err != nil {
			if first == nil {
				first = fmt.Errorf("offset %d: %w", p.offset, p.err)
				cancel()
			}
			stop = true
			continue
		}
		got[p.offset] = p.items
		if len(p.items) < nordPage {
			stop = true
		}
		if !stop {
			launch()
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return nil, first
	}
	offs := make([]int, 0, len(got))
	for off := range got {
		offs = append(offs, off)
	}
	sort.Ints(offs)
	seen := map[string]struct{}{}
	var all []nordServer
	for _, off := range offs {
		for _, s := range got[off] {
			key := s.Hostname
			if key == "" {
				key = s.IP
			}
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, s)
		}
	}
	if len(all) == 0 {
		return nil, errors.New("nordvpn api returned no servers")
	}
	return all, nil
}

func fetchNordPage(ctx context.Context, client *http.Client, offset int) ([]nordServer, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		items, err := fetchNordOnce(ctx, client, offset)
		if err == nil {
			return items, nil
		}
		last = err
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		var se *statusErr
		if errors.As(err, &se) && se.code < 500 && se.code != 429 {
			return nil, err
		}
		if attempt == 2 {
			break
		}
		t := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return nil, last
}

type statusErr struct {
	code int
	body string
}

func (e *statusErr) Error() string {
	if e.body == "" {
		return fmt.Sprintf("http %d", e.code)
	}
	return fmt.Sprintf("http %d: %s", e.code, e.body)
}

func fetchNordOnce(ctx context.Context, client *http.Client, offset int) ([]nordServer, error) {
	u := fmt.Sprintf("%s?limit=%d&offset=%d", nordAPI, nordPage, offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nordcheck/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		b := body
		if len(b) > 180 {
			b = b[:180]
		}
		return nil, &statusErr{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	return parseNord(body)
}

func nordClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = nordWorkers * 2
	tr.MaxIdleConnsPerHost = nordWorkers * 2
	tr.TLSHandshakeTimeout = 5 * time.Second
	tr.ResponseHeaderTimeout = 25 * time.Second
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	return &http.Client{Timeout: 40 * time.Second, Transport: tr}
}

type rawServer struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	Station   string `json:"station"`
	Load      int    `json:"load"`
	Status    string `json:"status"`
	Locations []struct {
		Country struct {
			Name string `json:"name"`
			Code string `json:"code"`
			City struct {
				Name string `json:"name"`
			} `json:"city"`
		} `json:"country"`
	} `json:"locations"`
	Groups []struct {
		Identifier string `json:"identifier"`
	} `json:"groups"`
	Services []struct {
		Identifier string `json:"identifier"`
	} `json:"services"`
	Technologies []struct {
		Identifier string `json:"identifier"`
		Metadata   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"metadata"`
	} `json:"technologies"`
	Specifications []struct {
		Identifier string `json:"identifier"`
		Values     []struct {
			Value string `json:"value"`
		} `json:"values"`
	} `json:"specifications"`
}

func parseNord(body []byte) ([]nordServer, error) {
	var raw []rawServer
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make([]nordServer, 0, len(raw))
	for _, item := range raw {
		s := nordServer{
			ID: item.ID, Name: item.Name, Hostname: item.Hostname,
			IP: item.Station, Load: item.Load, Status: item.Status,
		}
		if len(item.Locations) > 0 {
			c := item.Locations[0].Country
			s.Code, s.Country, s.City = c.Code, c.Name, c.City.Name
		}
		for _, g := range item.Groups {
			if id := strings.ToLower(strings.TrimSpace(g.Identifier)); id != "" {
				s.Groups = append(s.Groups, id)
			}
		}
		sort.Strings(s.Groups)
		for _, svc := range item.Services {
			if id := strings.ToLower(strings.TrimSpace(svc.Identifier)); id != "" {
				s.Services = append(s.Services, id)
			}
		}
		sort.Strings(s.Services)
		for _, t := range item.Technologies {
			id := strings.ToLower(strings.TrimSpace(t.Identifier))
			if id == "" {
				continue
			}
			s.Tech = append(s.Tech, id)
			if id == "wireguard_udp" && s.WGPub == "" {
				for _, m := range t.Metadata {
					if m.Name == "public_key" {
						s.WGPub = strings.TrimSpace(m.Value)
					}
				}
			}
		}
		s.Tech = orderTech(s.Tech)
		for _, spec := range item.Specifications {
			if spec.Identifier == "version" && len(spec.Values) > 0 {
				s.Version = spec.Values[0].Value
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func orderTech(ids []string) []string {
	set := map[string]struct{}{}
	for _, id := range ids {
		set[id] = struct{}{}
	}
	pref := []string{"wireguard_udp", "openvpn_udp", "openvpn_tcp", "ikev2", "nordwhisper", "nordwhisper_udp"}
	var out []string
	for _, id := range pref {
		if _, ok := set[id]; ok {
			out = append(out, id)
			delete(set, id)
		}
	}
	var rest []string
	for id := range set {
		rest = append(rest, id)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// scanProtos is what -proto asked to probe. full is every protocol plus the
// extra udp/53 and tcp/80 checks. The default is IKEv2 alone.
type scanProtos struct {
	full bool
	ike  bool
	wg   bool
	oudp bool
	otcp bool
}

func parseScanProtos(s string) (scanProtos, error) {
	var p scanProtos
	parts := splitComma(s)
	if len(parts) == 0 {
		return scanProtos{}, errors.New("-proto is empty")
	}
	for _, part := range parts {
		switch part {
		case "full", "all":
			p.full = true
		case "ikev2", "ike":
			p.ike = true
		case "wire", "wg", "wireguard", "wireguard_udp":
			p.wg = true
		case "openvpn", "ovpn":
			p.oudp, p.otcp = true, true
		case "openvpn_udp", "ovpn_udp", "ovpn-udp":
			p.oudp = true
		case "openvpn_tcp", "ovpn_tcp", "ovpn-tcp":
			p.otcp = true
		default:
			return scanProtos{}, fmt.Errorf("-proto: unknown %q (use ikev2, wire, openvpn, or full)", part)
		}
	}
	return p, nil
}

func (p scanProtos) onIKE() bool    { return p.full || p.ike }
func (p scanProtos) onWG() bool     { return p.full || p.wg }
func (p scanProtos) onOUDP() bool   { return p.full || p.oudp }
func (p scanProtos) onOTCP() bool   { return p.full || p.otcp }
func (p scanProtos) needsUDP() bool { return p.full || p.wg || p.oudp }

func (p scanProtos) match(s nordServer) bool {
	if p.full {
		return true
	}
	if p.ike && hasTech(s.Tech, "ikev2") {
		return true
	}
	if p.wg && hasTech(s.Tech, "wireguard_udp") {
		return true
	}
	if p.oudp && hasTech(s.Tech, "openvpn_udp") {
		return true
	}
	if p.otcp && hasTech(s.Tech, "openvpn_tcp") {
		return true
	}
	return false
}

func (p scanProtos) label() string {
	if p.full {
		return "full"
	}
	var names []string
	if p.ike {
		names = append(names, "ikev2")
	}
	if p.wg {
		names = append(names, "wire")
	}
	if p.oudp && p.otcp {
		names = append(names, "openvpn")
	} else if p.oudp {
		names = append(names, "openvpn_udp")
	} else if p.otcp {
		names = append(names, "openvpn_tcp")
	}
	return strings.Join(names, ",")
}

func (p scanProtos) portLine() string {
	if p.full {
		return "ports: wireguard udp/51820, openvpn udp/1194 and tcp/443, ikev2 udp/500 and udp/4500, extra udp/53 and tcp/80"
	}
	var parts []string
	if p.ike {
		parts = append(parts, "ikev2 udp/500 and udp/4500")
	}
	if p.wg {
		parts = append(parts, "wireguard udp/51820")
	}
	if p.oudp {
		parts = append(parts, "openvpn udp/1194")
	}
	if p.otcp {
		parts = append(parts, "openvpn tcp/443")
	}
	return "ports: " + strings.Join(parts, ", ")
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func countryOK(s nordServer, qs []string) bool {
	if len(qs) == 0 {
		return true
	}
	code := strings.ToLower(s.Code)
	country := strings.ToLower(s.Country)
	city := strings.ToLower(s.City)
	for _, q := range qs {
		if code == q || country == q {
			return true
		}
		if a, ok := nordAlias[q]; ok && code == a {
			return true
		}
		// Two-letter queries are country codes. A substring would match "us" inside "Austria".
		if len(q) > 2 && (strings.Contains(country, q) || strings.Contains(city, q)) {
			return true
		}
	}
	return false
}

var nordAlias = map[string]string{
	"uk":  "gb",
	"usa": "us",
	"uae": "ae",
}
