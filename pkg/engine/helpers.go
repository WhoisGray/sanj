package engine

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

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
		return "true"
	}
	return "false"
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
