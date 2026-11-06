package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whoisGray/vpnban/pkg/engine"
)

//go:embed all:desktop/frontend
var embeddedFrontend embed.FS

type guiServer struct {
	eng       *engine.Engine
	port      int
	clientsMu sync.Mutex
	clients   map[chan string]bool
}

func startGUIServer(port int, openBrowser bool) error {
	eng := engine.NewEngine()

	srv := &guiServer{
		eng:     eng,
		port:    port,
		clients: make(map[chan string]bool),
	}

	mux := http.NewServeMux()

	// API Endpoints
	mux.HandleFunc("/api/providers", srv.handleProviders)
	mux.HandleFunc("/api/servers", srv.handleServers)
	mux.HandleFunc("/api/probe", srv.handleProbe)
	mux.HandleFunc("/api/stop", srv.handleStop)
	mux.HandleFunc("/api/custom/parse", srv.handleCustomParse)
	mux.HandleFunc("/api/export", srv.handleExport)
	mux.HandleFunc("/api/events", srv.handleEvents)

	// Static Web Assets
	sub, err := fs.Sub(embeddedFrontend, "desktop/frontend")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("/", fileServer)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// Try next free port if default is taken
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", actualPort)

	fmt.Printf("🌐 vpnban Web GUI dashboard active at: %s\n", url)
	fmt.Println("Press Ctrl+C in terminal to stop.")

	if openBrowser {
		go openURL(url)
	}

	return http.Serve(listener, mux)
}

func (s *guiServer) handleProviders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.eng.GetProviders())
}

func (s *guiServer) handleServers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := q.Get("provider")
	country := q.Get("country")
	maxLoad, _ := strconv.Atoi(q.Get("maxLoad"))
	refresh := q.Get("refresh") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	servers, err := s.eng.FetchServers(ctx, provider, country, maxLoad, refresh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

type probeReq struct {
	Servers   []engine.UnifiedServer `json:"servers"`
	Protocols []string               `json:"protocols"`
}

func (s *guiServer) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req probeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results, err := s.eng.ProbeServers(context.Background(), req.Servers, req.Protocols, func(ev engine.ProbeEvent) {
		s.broadcastEvent(ev)
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"results": results,
	})
}

func (s *guiServer) handleStop(w http.ResponseWriter, r *http.Request) {
	s.eng.StopProbe()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

type customReq struct {
	Content     string `json:"content"`
	AllowPoison bool   `json:"allowPoison"`
}

func (s *guiServer) handleCustomParse(w http.ResponseWriter, r *http.Request) {
	var req customReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	staged, err := s.eng.ParseCustomInput(req.Content, req.AllowPoison)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(staged)
}

func (s *guiServer) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	var results []engine.UnifiedResult
	body, err := io.ReadAll(r.Body)
	if err == nil && len(body) > 0 {
		json.Unmarshal(body, &results)
	}

	data, mime, err := s.eng.ExportResults(format, results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(format)
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"vpnban-results.%s\"", ext))
	w.Write(data)
}

func (s *guiServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 10)
	s.clientsMu.Lock()
	s.clients[ch] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, ch)
		close(ch)
		s.clientsMu.Unlock()
	}()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *guiServer) broadcastEvent(ev engine.ProbeEvent) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- string(data):
		default:
		}
	}
}

func openURL(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	_ = exec.Command(cmd, args...).Start()
}
