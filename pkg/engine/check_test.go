package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestParseNordKeepsColumns(t *testing.T) {
	raw := []byte(`[{"id":7,"name":"Sweden #1","hostname":"se1.nordvpn.com","station":"1.2.3.4","load":3,"status":"online",
		"locations":[{"country":{"name":"Sweden","code":"SE","city":{"name":"Stockholm"}}}],
		"groups":[{"identifier":"legacy_p2p"},{"identifier":"europe"}],
		"services":[{"identifier":"vpn"},{"identifier":"proxy"}],
		"technologies":[
			{"identifier":"ikev2"},
			{"identifier":"wireguard_udp","metadata":[{"name":"public_key","value":"K53l2wOIHU3262sX5N/5kAvCvt4r55lNui30EbvaDlE="}]},
			{"identifier":"openvpn_udp"},
			{"identifier":"openvpn_tcp"}
		],
		"specifications":[{"identifier":"version","values":[{"value":"2.1.0"}]}]
	}]`)
	list, err := parseNord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("len %d", len(list))
	}
	s := list[0]
	if s.Name != "Sweden #1" || s.Hostname != "se1.nordvpn.com" || s.IP != "1.2.3.4" {
		t.Fatalf("identity %+v", s)
	}
	if s.Code != "SE" || s.City != "Stockholm" || s.Version != "2.1.0" {
		t.Fatalf("place %+v", s)
	}
	if stringsJoin(s.Services) != "proxy,vpn" || stringsJoin(s.Groups) != "europe,legacy_p2p" {
		t.Fatalf("cols %+v %+v", s.Services, s.Groups)
	}
	if stringsJoin(s.Tech) != "wireguard_udp,openvpn_udp,openvpn_tcp,ikev2" {
		t.Fatalf("tech %v", s.Tech)
	}
	if _, err := decodeWGKey(s.WGPub); err != nil {
		t.Fatal(err)
	}
	if !countryOK(s, []string{"se"}) || !countryOK(s, []string{"sweden"}) || countryOK(s, []string{"us"}) {
		t.Fatalf("country filter %+v", s)
	}
}

func stringsJoin(s []string) string {
	out := ""
	for i, p := range s {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

func TestScoreFresh(t *testing.T) {
	base := nordHit{HasWG: true, HasOUDP: true, HasOTCP: true, HasIKE: true, WG: "silent", OUDP: "silent", OTCP: "silent", U53: "silent", T80: "closed"}
	h := base
	h.IKE = "real"
	if fresh, wall := scoreHit(h); fresh != "yes" || wall != "clean" {
		t.Fatalf("ike real: %s %s", fresh, wall)
	}
	h = base
	h.IKE = "p1"
	if fresh, wall := scoreHit(h); fresh != "yes" || wall != "phase1" {
		t.Fatalf("ike p1: %s %s", fresh, wall)
	}
	h = base
	h.IKE = "real"
	h.WG = "fake"
	if fresh, wall := scoreHit(h); fresh != "no" || wall != "inject" {
		t.Fatalf("wg fake: %s %s", fresh, wall)
	}
	h = base
	h.IKE = "real"
	h.OTCP = "other"
	if fresh, wall := scoreHit(h); fresh != "no" || wall != "intercept" {
		t.Fatalf("tcp intercept: %s %s", fresh, wall)
	}
	h = base
	h.IKE = "silent"
	h.U53 = "other"
	if fresh, _ := scoreHit(h); fresh != "unproven" {
		t.Fatalf("dns other should not fail a silent server: %s", fresh)
	}
	h = base
	h.HasOTCP = true
	h.IKE = "real"
	h.OTCP = "closed"
	if fresh, wall := scoreHit(h); fresh != "no" || wall != "blocked" {
		t.Fatalf("closed openvpn: %s %s", fresh, wall)
	}
}

func TestWGCookieVersusFake(t *testing.T) {
	pub := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	mac1Key, cookieKey := wgMACKeys(pub)
	_, sender, mac1 := buildWG(&mac1Key, true)
	reply := sealCookie(t, cookieKey[:], mac1, sender)
	if st, _ := judgeWG([][]byte{reply}, sender, sender+9, mac1, cookieKey[:]); st != "real" {
		t.Fatalf("cookie: %s", st)
	}
	junk := []byte("not-wireguard")
	if st, detail := judgeWG([][]byte{reply, junk}, sender, sender+9, mac1, cookieKey[:]); st != "fake" {
		t.Fatalf("junk beside cookie: %s %s", st, detail)
	}
	bad := append([]byte(nil), reply...)
	binary.LittleEndian.PutUint32(bad[4:8], sender+9)
	if st, detail := judgeWG([][]byte{bad}, sender, sender+9, mac1, cookieKey[:]); st != "fake" || detail != "replied to bad mac1" {
		t.Fatalf("bad mac1: %s %s", st, detail)
	}
	if st, _ := judgeWG(nil, sender, 2, mac1, cookieKey[:]); st != "silent" {
		t.Fatalf("silent: %s", st)
	}
	// A different public key must not open this cookie.
	other := make([]byte, 32)
	other[0] = 1
	_, otherCookie := wgMACKeys(other)
	if cookieOK(reply, mac1, otherCookie[:], sender) {
		t.Fatal("cookie opened under the wrong server key")
	}
}

func sealCookie(t *testing.T, cookieKey, mac1 []byte, sender uint32) []byte {
	t.Helper()
	reply := make([]byte, wgCookieSize)
	binary.LittleEndian.PutUint32(reply[0:4], 3)
	binary.LittleEndian.PutUint32(reply[4:8], sender)
	if _, err := rand.Read(reply[8:32]); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(cookieKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, reply[8:32], []byte("0123456789abcdef"), mac1)
	if len(ct) != 32 {
		t.Fatalf("cookie ct %d", len(ct))
	}
	copy(reply[32:], ct)
	return reply
}

func TestParseScanProtos(t *testing.T) {
	ike, err := parseScanProtos("ikev2")
	if err != nil || ike.label() != "ikev2" || !ike.onIKE() || ike.onWG() || ike.needsUDP() {
		t.Fatalf("default %+v %v", ike, err)
	}
	both, err := parseScanProtos("IKEV2, wire")
	if err != nil || both.label() != "ikev2,wire" || !both.onIKE() || !both.onWG() || both.full {
		t.Fatalf("list %+v %v", both, err)
	}
	full, err := parseScanProtos("full")
	if err != nil || !full.full || full.label() != "full" || !full.onOTCP() || !full.needsUDP() {
		t.Fatalf("full %+v %v", full, err)
	}
	if _, err := parseScanProtos("pptp"); err == nil {
		t.Fatal("expected unknown protocol")
	}
	s := nordServer{Tech: []string{"wireguard_udp", "openvpn_udp"}}
	if ike.match(s) || !both.match(s) || !full.match(s) {
		t.Fatalf("match ike %v both %v full %v", ike.match(s), both.match(s), full.match(s))
	}
	onlyIKE := nordServer{Tech: []string{"ikev2"}}
	if !ike.match(onlyIKE) || !both.match(onlyIKE) {
		t.Fatal("ike server should match ikev2 and ikev2,wire")
	}
}

func TestOpenVPNJudge(t *testing.T) {
	pkt, sid := ovpnHardReset()
	if len(pkt) != 14 || pkt[0] != 0x38 {
		t.Fatalf("reset %#v", pkt)
	}
	reply := make([]byte, 26)
	reply[0] = 8 << 3
	copy(reply[14:22], sid)
	if st, _ := judgeOVPN(reply, sid, false, portOUDP); st != "real" {
		t.Fatalf("server reset: %s", st)
	}
	if st, detail := judgeOVPN(pkt, sid, false, portOUDP); st != "fake" || detail != "echo of client hard-reset" {
		t.Fatalf("echo: %s %s", st, detail)
	}
	frame := append([]byte{0, byte(len(reply))}, reply...)
	if st, _ := judgeOVPN(frame, sid, true, portOTCP); st != "real" {
		t.Fatalf("tcp frame: %s", st)
	}
	tls := []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x01}
	if st, detail := judgeOVPN(tls, sid, false, portOTCP); st != "other" || detail != "tls" {
		t.Fatalf("tls: %s %s", st, detail)
	}
	dns := []byte{0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if st, _ := judgeOVPN(dns, sid, false, portDNS); st != "other" {
		t.Fatalf("dns: %s", st)
	}
	if st, _ := judgeOVPN([]byte("garbage!!"), sid, false, portOUDP); st != "fake" {
		t.Fatalf("garbage: %s", st)
	}
}

func TestIKEPoolPacket(t *testing.T) {
	prime, ok := new(big.Int).SetString(modp2048, 16)
	if !ok {
		t.Fatal("prime")
	}
	warmIKE(prime, 4)
	_, spi1, _, p1 := buildSAInitPacket(prime)
	_, spi2, _, p2 := buildSAInitPacket(prime)
	if len(p1) < 200 || p1[18] != 34 || len(spi1) != 8 {
		t.Fatalf("packet %d %v", len(p1), p1[:20])
	}
	same := true
	for i := range spi1 {
		if spi1[i] != spi2[i] {
			same = false
		}
	}
	if same {
		t.Fatal("pool reused one SPI")
	}
	if string(p2) == "" {
		t.Fatal("empty")
	}
}

func TestUDPCollectReturnsEarly(t *testing.T) {
	pool, err := newUDPPool(1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		_, addr, err := srv.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = srv.WriteToUDP([]byte("junk-packet"), addr)
	}()
	port := srv.LocalAddr().(*net.UDPAddr).Port
	start := time.Now()
	got, err := pool.collect(context.Background(), "127.0.0.1", port, [][]byte{[]byte("hi")}, 800*time.Millisecond, func(p [][]byte) bool {
		return len(p) > 0
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatalf("waited %s", time.Since(start))
	}
	if len(got) != 1 || string(got[0]) != "junk-packet" {
		t.Fatalf("%q", got)
	}
}
