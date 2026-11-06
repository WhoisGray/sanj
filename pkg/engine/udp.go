package engine

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// errBusy means this socket already has a probe in flight to that ip:port.
var errBusy = errors.New("udp socket busy")

// udpSock is one unbound UDP socket. Many probes share it. Replies are matched
// on the remote ip and port, so one read loop serves every worker.
type udpSock struct {
	pc   *net.UDPConn
	mu   sync.Mutex
	wait map[string]chan []byte
}

type udpPool struct {
	socks []*udpSock
	n     atomic.Uint32
}

func newUDPPool(n int) (*udpPool, error) {
	if n < 1 {
		n = 1
	}
	if n > 32 {
		n = 32
	}
	p := &udpPool{socks: make([]*udpSock, 0, n)}
	for i := 0; i < n; i++ {
		s, err := newUDPSock()
		if err != nil {
			p.Close()
			return nil, err
		}
		p.socks = append(p.socks, s)
	}
	return p, nil
}

func newUDPSock() (*udpSock, error) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	_ = pc.SetReadBuffer(4 << 20)
	_ = pc.SetWriteBuffer(1 << 20)
	s := &udpSock{pc: pc, wait: map[string]chan []byte{}}
	go s.loop()
	return s, nil
}

func (p *udpPool) Close() {
	for _, s := range p.socks {
		_ = s.pc.Close()
	}
}

func (p *udpPool) collect(ctx context.Context, ip string, port int, pkts [][]byte, timeout time.Duration, stop func([][]byte) bool) ([][]byte, error) {
	if len(p.socks) == 0 {
		return nil, errors.New("no udp socket")
	}
	start := int(p.n.Add(1))
	var last error
	for i := range p.socks {
		got, err := p.socks[(start+i)%len(p.socks)].collect(ctx, ip, port, pkts, timeout, stop)
		if !errors.Is(err, errBusy) {
			return got, err
		}
		last = err
	}
	return nil, last
}

func (u *udpSock) loop() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := u.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 || addr == nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		key := udpKey(addr.IP, addr.Port)
		u.mu.Lock()
		ch := u.wait[key]
		u.mu.Unlock()
		if ch == nil {
			continue
		}
		select {
		case ch <- pkt:
		default:
		}
	}
}

func (u *udpSock) collect(ctx context.Context, ip string, port int, pkts [][]byte, timeout time.Duration, stop func([][]byte) bool) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return nil, errors.New("not ipv4")
	}
	addr := &net.UDPAddr{IP: dst, Port: port}
	key := udpKey(dst, port)
	ch := make(chan []byte, 8)
	u.mu.Lock()
	if _, busy := u.wait[key]; busy {
		u.mu.Unlock()
		return nil, errBusy
	}
	u.wait[key] = ch
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		delete(u.wait, key)
		u.mu.Unlock()
	}()

	for _, p := range pkts {
		if _, err := u.pc.WriteToUDP(p, addr); err != nil {
			return nil, err
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var got [][]byte
	for {
		select {
		case <-ctx.Done():
			return got, ctx.Err()
		case b := <-ch:
			got = append(got, b)
			if stop != nil && stop(got) {
				return got, nil
			}
		case <-timer.C:
			return got, nil
		}
	}
}

func udpKey(ip net.IP, port int) string {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}
