package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// WireGuard handshake sizes and labels, from wireguard-go.
const (
	wgInitSize    = 148
	wgCookieSize  = 64
	wgLabelMAC1   = "mac1----"
	wgLabelCookie = "cookie--"
	portWG        = 51820
)

func decodeWGKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty wireguard key")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("bad wireguard key")
	}
	return b, nil
}

func wgMACKeys(pub []byte) (mac1Key, cookieKey [32]byte) {
	h, _ := blake2s.New256(nil)
	h.Write([]byte(wgLabelMAC1))
	h.Write(pub)
	h.Sum(mac1Key[:0])
	h.Reset()
	h.Write([]byte(wgLabelCookie))
	h.Write(pub)
	h.Sum(cookieKey[:0])
	return mac1Key, cookieKey
}

// buildWG builds a handshake initiation. The static field is random on purpose:
// the server has no peer for that key, so a real server never completes a session.
// good mac1 is sealed with the server's published public key. A bad mac1 is noise.
// A real server drops the bad packet. It answers the good one only with a cookie,
// and only when it is under load. Anything else is not WireGuard.
func buildWG(mac1Key *[32]byte, good bool) (pkt []byte, sender uint32, mac1 []byte) {
	pkt = make([]byte, wgInitSize)
	binary.LittleEndian.PutUint32(pkt[0:4], 1)
	var sb [4]byte
	_, _ = rand.Read(sb[:])
	sender = binary.LittleEndian.Uint32(sb[:])
	if sender == 0 {
		sender = 1
	}
	binary.LittleEndian.PutUint32(pkt[4:8], sender)
	if key, err := ecdh.X25519().GenerateKey(rand.Reader); err == nil {
		copy(pkt[8:40], key.PublicKey().Bytes())
	} else {
		_, _ = rand.Read(pkt[8:40])
	}
	_, _ = rand.Read(pkt[40:116])
	if good && mac1Key != nil {
		mac, _ := blake2s.New128(mac1Key[:])
		mac.Write(pkt[:116])
		sum := mac.Sum(nil)
		copy(pkt[116:132], sum)
	} else {
		_, _ = rand.Read(pkt[116:132])
	}
	mac1 = append([]byte(nil), pkt[116:132]...)
	return pkt, sender, mac1
}

// cookieOK is true when the reply is a type-3 cookie, addressed to our sender
// index, that opens with the key derived from the server public key.
func cookieOK(reply, mac1, cookieKey []byte, sender uint32) bool {
	if len(reply) != wgCookieSize || len(mac1) != 16 || len(cookieKey) != 32 {
		return false
	}
	if binary.LittleEndian.Uint32(reply[0:4]) != 3 {
		return false
	}
	if binary.LittleEndian.Uint32(reply[4:8]) != sender {
		return false
	}
	aead, err := chacha20poly1305.NewX(cookieKey)
	if err != nil {
		return false
	}
	_, err = aead.Open(nil, reply[8:32], reply[32:64], mac1)
	return err == nil
}

func judgeWG(replies [][]byte, goodSender, badSender uint32, mac1, cookieKey []byte) (string, string) {
	if len(replies) == 0 {
		return "silent", "no reply"
	}
	good := 0
	for _, r := range replies {
		if cookieOK(r, mac1, cookieKey, goodSender) {
			good++
			continue
		}
		if len(r) >= 8 && binary.LittleEndian.Uint32(r[0:4]) == 3 && binary.LittleEndian.Uint32(r[4:8]) == badSender {
			return "fake", "replied to bad mac1"
		}
		if len(r) >= 4 && binary.LittleEndian.Uint32(r[0:4]) == 2 {
			return "fake", "handshake response to unknown key"
		}
		if len(r) >= 9 && r[0] == 1 && binary.LittleEndian.Uint32(r[4:8]) == goodSender {
			return "fake", "echo"
		}
		return "fake", sniff(r)
	}
	if good > 0 {
		return "real", "cookie sealed to server public key"
	}
	return "fake", "unclassified"
}

func sniff(r []byte) string {
	if len(r) == 0 {
		return "empty"
	}
	if looksLikeTLS(r) {
		return "tls"
	}
	if looksLikeHTTP(r) {
		return "http"
	}
	n := len(r)
	if n > 8 {
		n = 8
	}
	return "payload " + base64.RawStdEncoding.EncodeToString(r[:n])
}
