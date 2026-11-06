package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// NordVPN OpenVPN listens on UDP 1194 and TCP 443.
// UDP 53 and TCP 80 are not NordVPN OpenVPN ports. They are probed so a firewall
// that injects a packet on a common port shows up in the sheet.
const (
	portOUDP = 1194
	portOTCP = 443
	portDNS  = 53
	portHTTP = 80
)

// shortcut: bare hard-reset, no tls-auth. Nord often stays silent; a published tls-auth key would be the upgrade.

func ovpnHardReset() (pkt, sid []byte) {
	pkt = make([]byte, 14)
	pkt[0] = 7 << 3 // P_CONTROL_HARD_RESET_CLIENT_V2
	_, _ = rand.Read(pkt[1:9])
	sid = append([]byte(nil), pkt[1:9]...)
	return pkt, sid
}

func judgeOVPN(reply, sid []byte, tcp bool, port int) (string, string) {
	body := reply
	if tcp && len(reply) >= 2 {
		n := int(binary.BigEndian.Uint16(reply[:2]))
		if n > 0 && 2+n <= len(reply) {
			body = reply[2 : 2+n]
		} else if n > len(reply)-2 && n < 1500 {
			return "unproven", "short tcp read"
		}
	}
	if len(body) == 0 {
		return "fake", "empty"
	}
	if len(body) >= 9 && body[0] == 0x38 && bytesEqual(body[1:9], sid) {
		return "fake", "echo of client hard-reset"
	}
	op := body[0] >> 3
	if op >= 1 && op <= 10 && bytesContain(body, sid) && op != 7 {
		return "real", "openvpn acked session"
	}
	if looksLikeTLS(body) {
		return "other", "tls"
	}
	if looksLikeHTTP(body) {
		return "other", "http"
	}
	if port == portDNS && looksLikeDNS(body) {
		return "other", "dns"
	}
	return "fake", sniff(body)
}

func looksLikeTLS(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

func looksLikeHTTP(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	s := strings.ToUpper(string(b[:min(8, len(b))]))
	return strings.HasPrefix(s, "HTTP") || strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "<!") || strings.HasPrefix(s, "<HTML")
}

func looksLikeDNS(b []byte) bool {
	if len(b) < 12 || b[2]&0x80 == 0 {
		return false
	}
	qd := int(b[4])<<8 | int(b[5])
	return qd <= 10
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesContain(hay, needle []byte) bool {
	if len(needle) == 0 || len(hay) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if bytesEqual(hay[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func probeOVPNTCP(ctx context.Context, ip string, port int, timeout time.Duration) (string, string, int) {
	pkt, sid := ovpnHardReset()
	frame := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(pkt)))
	copy(frame[2:], pkt)
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		if ctx.Err() != nil {
			return "silent", "interrupted", -1
		}
		if refused(err) {
			return "closed", "tcp refused", -1
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "silent", "tcp timeout", -1
		}
		return "silent", "dial: " + err.Error(), -1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(frame); err != nil {
		return "closed", "tcp write failed", -1
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "silent", "tcp open, no openvpn", -1
	}
	ms := int(time.Since(start).Milliseconds())
	st, detail := judgeOVPN(buf[:n], sid, true, port)
	return st, detail, ms
}

func refused(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) {
		return errors.Is(op.Err, syscall.ECONNREFUSED)
	}
	return false
}
