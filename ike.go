package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RFC 3526 MODP 2048-bit Diffie-Hellman Group 14
const modp2048 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

type ikeResult struct {
	OK         bool
	Port       int
	RTT        time.Duration
	Phase1     string
	Phase2     string
	AuthStatus string
}

func u16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func prf256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func prfPlus256(key, seed []byte, total int) []byte {
	var out, prev []byte
	counter := byte(1)
	for len(out) < total {
		h := hmac.New(sha256.New, key)
		if len(prev) > 0 {
			h.Write(prev)
		}
		h.Write(seed)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:total]
}

const (
	statusOK          = "✅ ok"
	statusNoReply     = "⏳ no reply"
	statusConnectErr  = "❌ connect error"
	statusSendErr     = "❌ send error"
	statusFakeSPI     = "🚫 fake (bad SPI)"
	statusFakeType    = "🚫 fake (bad response)"
	statusFakeSPIr    = "🚫 fake (empty SPIr)"
	statusIncomplete  = "⚠️ incomplete (no KE/Nonce)"
	statusFakeSend    = "🚫 fake (send error)"
	statusFakeTimeout = "🚫 fake (no reply)"
	statusFakePacket  = "🚫 fake (bad packet)"
	statusFakeSig     = "🚫 fake (bad signature)"
	statusFakeDecrypt = "🚫 fake (decrypt error)"
	statusFakePlain   = "🚫 fake (not encrypted)"

	authSendErr   = "❌ auth send failed"
	authTimeout   = "⏳ phase 1 replied, phase 2 timed out"
	authBadPacket = "🚫 phase 2 response is invalid"
	authBadSig    = "🚫 phase 2 signature is invalid"
	authBadPad    = "🚫 decrypt padding is invalid"
	authEAP       = "✅ verified (real EAP/Cert server)"
	authRejected  = "✅ verified (real server rejected auth)"
	authDecryptOK = "✅ decrypt succeeded"
	authPlain     = "🚫 phase 2 response is not encrypted"
)

// ikeMaterial is a client Diffie-Hellman keypair. The scan builds a pool of these
// once. A 2048-bit exponentiation per probe was the slow part of the checker.
type ikeMaterial struct {
	priv *big.Int
	ke   []byte
}

var (
	ikeMat  []ikeMaterial
	ikeMatN atomic.Uint32
)

func warmIKE(prime *big.Int, n int) {
	if n < 1 {
		n = 1
	}
	if len(ikeMat) >= n {
		return
	}
	mat := make([]ikeMaterial, n)
	var wg sync.WaitGroup
	for i := range mat {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mat[i] = newIKEMaterial(prime)
		}(i)
	}
	wg.Wait()
	ikeMat = mat
}

func newIKEMaterial(prime *big.Int) ikeMaterial {
	priv, err := rand.Int(rand.Reader, prime)
	if err != nil || priv.Sign() == 0 {
		priv = big.NewInt(3)
	}
	raw := new(big.Int).Exp(big.NewInt(2), priv, prime).Bytes()
	ke := make([]byte, 256)
	if len(raw) > 256 {
		copy(ke, raw[len(raw)-256:])
	} else {
		copy(ke[256-len(raw):], raw)
	}
	return ikeMaterial{priv: priv, ke: ke}
}

func takeIKE(prime *big.Int) (*big.Int, []byte) {
	if n := len(ikeMat); n > 0 {
		m := ikeMat[int(ikeMatN.Add(1)-1)%n]
		return m.priv, m.ke
	}
	m := newIKEMaterial(prime)
	return m.priv, m.ke
}

// buildSAInitPacket builds an IKE_SA_INIT packet. The Diffie-Hellman public key
// comes from the pool when warmIKE has run.
func buildSAInitPacket(prime *big.Int) (priv *big.Int, spii, ni, plain []byte) {
	priv, ke := takeIKE(prime)

	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:2], 0x8000|14)
	binary.BigEndian.PutUint16(attr[2:4], 256)

	transform := func(last bool, typ, id byte, extra []byte) []byte {
		flag := byte(3)
		if last {
			flag = 0
		}
		body := append([]byte{typ, 0}, append(u16(int(id)), extra...)...)
		out := append([]byte{flag, 0}, u16(4+len(body))...)
		return append(out, body...)
	}

	transforms := append(transform(false, 1, 12, attr), transform(false, 2, 5, nil)...)
	transforms = append(transforms, transform(false, 3, 12, nil)...)
	transforms = append(transforms, transform(true, 4, 14, nil)...)

	proposal := append([]byte{0, 0}, u16(8+len(transforms))...)
	proposal = append(proposal, 1, 1, 0, 4)
	proposal = append(proposal, transforms...)

	sa := append([]byte{34, 0}, u16(4+len(proposal))...)
	sa = append(sa, proposal...)

	keBody := append(u16(14), 0, 0)
	keBody = append(keBody, ke...)
	kePayload := append([]byte{40, 0}, u16(4+len(keBody))...)
	kePayload = append(kePayload, keBody...)

	ni = make([]byte, 32)
	_, _ = rand.Read(ni)
	noncePayload := append([]byte{0, 0}, u16(4+len(ni))...)
	noncePayload = append(noncePayload, ni...)

	body := append(sa, kePayload...)
	body = append(body, noncePayload...)

	hdr := make([]byte, 28)
	_, _ = rand.Read(hdr[:8])
	spii = make([]byte, 8)
	copy(spii, hdr[:8])
	hdr[16] = 33
	hdr[17] = 0x20
	hdr[18] = 34
	hdr[19] = 0x08
	binary.BigEndian.PutUint32(hdr[24:28], uint32(28+len(body)))
	plain = append(hdr, body...)
	return priv, spii, ni, plain
}

// probeIKEEndpoint checks both IKEv2 phases on one port.
func probeIKEEndpoint(ip string, port int, prime *big.Int, ikeUser, remoteID string, timeout time.Duration) (res ikeResult, ok bool) {
	priv, spii, ni, plain := buildSAInitPacket(prime)

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ikeResult{Phase1: statusConnectErr, Phase2: "-"}, false
	}
	defer conn.Close()

	toSend := plain
	if port == 4500 {
		toSend = append([]byte{0, 0, 0, 0}, plain...)
	}

	start := time.Now()
	_ = conn.SetDeadline(start.Add(timeout))
	if _, err := conn.Write(toSend); err != nil {
		return ikeResult{Phase1: statusSendErr, Phase2: "-"}, false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ikeResult{Phase1: statusNoReply, Phase2: "-"}, false
	}
	rtt := time.Since(start)
	if rtt < time.Millisecond {
		rtt = time.Millisecond
	}

	resp := buf[:n]
	if len(resp) >= 32 && binary.BigEndian.Uint32(resp[:4]) == 0 {
		resp = resp[4:]
	}

	// Validate the phase 1 response.
	if len(resp) < 28 || !bytes.Equal(resp[:8], spii) {
		return ikeResult{Phase1: statusFakeSPI, Phase2: "-", Port: port}, false
	}
	if resp[18] != 34 || resp[19]&0x20 == 0 {
		return ikeResult{Phase1: statusFakeType, Phase2: "-", Port: port}, false
	}

	spir := make([]byte, 8)
	copy(spir, resp[8:16])
	if bytes.Equal(spir, make([]byte, 8)) {
		return ikeResult{Phase1: statusFakeSPIr, Phase2: "-", Port: port}, false
	}

	// Extract KEr and Nr.
	var ker, nr []byte
	offset := 28
	next := resp[16]
	for offset < len(resp) && next != 0 {
		curr := next
		if offset+4 > len(resp) {
			break
		}
		next = resp[offset]
		plen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		if plen < 4 || offset+plen > len(resp) {
			break
		}
		data := resp[offset+4 : offset+plen]
		if curr == 34 && len(data) >= 4 { // KE
			ker = data[4:]
		} else if curr == 40 { // Nonce
			nr = data
		}
		offset += plen
	}

	if len(ker) == 0 || len(nr) == 0 {
		return ikeResult{Phase1: statusIncomplete, Phase2: "-", Port: port}, false
	}

	// Phase 1 is fully verified.
	res = ikeResult{
		OK:     true,
		Port:   port,
		RTT:    rtt,
		Phase1: statusOK,
	}

	// Phase 2: encrypted IKE_AUTH.
	pubR := new(big.Int).SetBytes(ker)
	dhShared := new(big.Int).Exp(pubR, priv, prime).Bytes()
	if len(dhShared) < 256 {
		p := make([]byte, 256)
		copy(p[256-len(dhShared):], dhShared)
		dhShared = p
	}

	seedInput := append(append([]byte{}, ni...), nr...)
	skeyseed := prf256(seedInput, dhShared)

	keySeed := append(append(append(append([]byte{}, ni...), nr...), spii...), spir...)
	keyMat := prfPlus256(skeyseed, keySeed, 224)
	skAi := keyMat[32:64]
	skAr := keyMat[64:96]
	skEi := keyMat[96:128]
	skEr := keyMat[128:160]

	// Encrypted payloads: IDi and IDr.
	idiBody := append([]byte{3, 0, 0, 0}, []byte(ikeUser)...) // ID_RFC822_ADDR
	idiPayload := append([]byte{36, 0}, u16(4+len(idiBody))...)
	idiPayload = append(idiPayload, idiBody...)

	idrBody := append([]byte{2, 0, 0, 0}, []byte(remoteID)...) // ID_FQDN
	idrPayload := append([]byte{0, 0}, u16(4+len(idrBody))...)
	idrPayload = append(idrPayload, idrBody...)

	innerPlain := append(idiPayload, idrPayload...)
	padLen := 16 - ((len(innerPlain) + 1) % 16)
	if padLen == 16 {
		padLen = 0
	}
	padding := make([]byte, padLen)
	innerPlain = append(append(innerPlain, padding...), byte(padLen))

	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	block, _ := aes.NewCipher(skEi)
	cbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(innerPlain))
	cbc.CryptBlocks(ciphertext, innerPlain)

	skHdr := append([]byte{35, 0}, u16(4+16+len(ciphertext)+16)...)

	authHdr := make([]byte, 28)
	copy(authHdr[0:8], spii)
	copy(authHdr[8:16], spir)
	authHdr[16] = 46
	authHdr[17] = 0x20
	authHdr[18] = 35 // IKE_AUTH
	authHdr[19] = 0x08
	binary.BigEndian.PutUint32(authHdr[20:24], 1)
	totalLen := 28 + 4 + 16 + len(ciphertext) + 16
	binary.BigEndian.PutUint32(authHdr[24:28], uint32(totalLen))

	h := hmac.New(sha256.New, skAi)
	h.Write(authHdr)
	h.Write(skHdr)
	h.Write(iv)
	h.Write(ciphertext)
	icv := h.Sum(nil)[:16]

	authPacket := append(authHdr, skHdr...)
	authPacket = append(authPacket, iv...)
	authPacket = append(authPacket, ciphertext...)
	authPacket = append(authPacket, icv...)

	sendAuth := authPacket
	if port == 4500 {
		sendAuth = append([]byte{0, 0, 0, 0}, authPacket...)
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(sendAuth); err != nil {
		res.Phase2 = statusFakeSend
		res.AuthStatus = authSendErr
		return res, true
	}

	n, err = conn.Read(buf)
	if err != nil {
		res.Phase2 = statusFakeTimeout
		res.AuthStatus = authTimeout
		return res, true
	}

	respAuth := buf[:n]
	if len(respAuth) >= 32 && binary.BigEndian.Uint32(respAuth[:4]) == 0 {
		respAuth = respAuth[4:]
	}

	if len(respAuth) < 28 || respAuth[18] != 35 || respAuth[19]&0x20 == 0 {
		res.Phase2 = statusFakePacket
		res.AuthStatus = authBadPacket
		return res, true
	}

	if respAuth[16] == 46 && len(respAuth) > 28+4+16+16 {
		respIv := respAuth[32 : 32+16]
		respEnc := respAuth[32+16 : len(respAuth)-16]
		respIcv := respAuth[len(respAuth)-16:]

		hVerify := hmac.New(sha256.New, skAr)
		hVerify.Write(respAuth[:len(respAuth)-16])
		if !bytes.Equal(respIcv, hVerify.Sum(nil)[:16]) {
			res.Phase2 = statusFakeSig
			res.AuthStatus = authBadSig
			return res, true
		}

		decBlock, _ := aes.NewCipher(skEr)
		decCbc := cipher.NewCBCDecrypter(decBlock, respIv)
		decrypted := make([]byte, len(respEnc))
		decCbc.CryptBlocks(decrypted, respEnc)
		padLength := int(decrypted[len(decrypted)-1])
		if padLength > len(decrypted)-1 {
			res.Phase2 = statusFakeDecrypt
			res.AuthStatus = authBadPad
			return res, true
		}
		decPlain := decrypted[:len(decrypted)-1-padLength]

		// Inspect the decrypted payload.
		inNext := respAuth[28]
		inOff := 0
		hasEAP := false
		hasCert := false
		notifyCode := 0
		for inOff < len(decPlain) && inNext != 0 {
			pType := inNext
			if inOff+4 > len(decPlain) {
				break
			}
			inNext = decPlain[inOff]
			pLen := int(binary.BigEndian.Uint16(decPlain[inOff+2 : inOff+4]))
			if pLen < 4 || inOff+pLen > len(decPlain) {
				break
			}
			pData := decPlain[inOff+4 : inOff+pLen]
			if pType == 48 {
				hasEAP = true
			} else if pType == 37 {
				hasCert = true
			} else if pType == 41 && len(pData) >= 4 {
				notifyCode = int(binary.BigEndian.Uint16(pData[2:4]))
			}
			inOff += pLen
		}

		res.Phase2 = statusOK
		if hasEAP || hasCert {
			res.AuthStatus = authEAP
		} else if notifyCode == 24 {
			res.AuthStatus = authRejected
		} else if notifyCode > 0 {
			res.AuthStatus = fmt.Sprintf("📣 server: NOTIFY %d", notifyCode)
		} else {
			res.AuthStatus = authDecryptOK
		}
		return res, true
	}

	res.Phase2 = statusFakePlain
	res.AuthStatus = authPlain
	return res, true
}

// probeIKE tries port 500 first. If there is no reply, it tries port 4500.
func probeIKE(ip string, prime *big.Int, ikeUser, remoteID string, timeout time.Duration) ikeResult {
	// Port 500 is preferred; switch to 4500 when NAT-T is required.
	res, ok := probeIKEEndpoint(ip, 500, prime, ikeUser, remoteID, timeout)
	if ok && res.Phase1 == statusOK {
		return res
	}
	res4500, ok4500 := probeIKEEndpoint(ip, 4500, prime, ikeUser, remoteID, timeout)
	if ok4500 && res4500.Phase1 == statusOK {
		return res4500
	}
	if res.Phase1 != statusNoReply {
		return res
	}
	return res4500
}

func tcpRTT(ip string, port int, timeout time.Duration) (time.Duration, bool) {
	addr := net.JoinHostPort(ip, itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, false
	}
	_ = conn.Close()
	ms := time.Since(start)
	if ms < time.Millisecond {
		ms = time.Millisecond
	}
	return ms, true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
