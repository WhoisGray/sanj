package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/whoisGray/vpnban/pkg/engine"
)

// App struct
type App struct {
	ctx    context.Context
	engine *engine.Engine
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		engine: engine.NewEngine(),
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) GetProviders() []engine.ProviderInfo {
	return a.engine.GetProviders()
}

func (a *App) FetchServers(provider, country string, maxLoad int, refresh bool) ([]engine.UnifiedServer, error) {
	return a.engine.FetchServers(a.ctx, provider, country, maxLoad, refresh)
}

func (a *App) ProbeServers(servers []engine.UnifiedServer, protos []string) ([]engine.UnifiedResult, error) {
	return a.engine.ProbeServers(a.ctx, servers, protos, func(ev engine.ProbeEvent) {
		runtime.EventsEmit(a.ctx, "probe_event", ev)
	})
}

func (a *App) StopProbe() {
	a.engine.StopProbe()
}

func (a *App) ParseCustomInput(content string, allowPoison bool) ([]engine.CustomStagedNode, error) {
	return a.engine.ParseCustomInput(content, allowPoison)
}

func (a *App) SelectFile() (string, string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select VPN Server Catalog or Hostlist",
		Filters: []runtime.FileFilter{
			{DisplayName: "All Supported (*.txt, *.json, *.csv)", Pattern: "*.txt;*.json;*.csv"},
			{DisplayName: "Text Hostlist (*.txt)", Pattern: "*.txt"},
			{DisplayName: "JSON Catalog (*.json)", Pattern: "*.json"},
		},
	})
	if err != nil || path == "" {
		return "", "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	return path, string(data), nil
}

func (a *App) SaveExportFile(format string, results []engine.UnifiedResult) (string, error) {
	ext := "json"
	filter := runtime.FileFilter{DisplayName: "JSON File (*.json)", Pattern: "*.json"}
	if format == "csv" {
		ext = "csv"
		filter = runtime.FileFilter{DisplayName: "CSV File (*.csv)", Pattern: "*.csv"}
	} else if format == "xlsx" {
		ext = "xlsx"
		filter = runtime.FileFilter{DisplayName: "Excel Spreadsheet (*.xlsx)", Pattern: "*.xlsx"}
	}

	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           fmt.Sprintf("Export Results to %s", format),
		DefaultFilename: fmt.Sprintf("vpnban-results.%s", ext),
		Filters:         []runtime.FileFilter{filter},
	})
	if err != nil || path == "" {
		return "", err
	}

	data, _, err := a.engine.ExportResults(format, results)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func (a *App) ExportBase64(format string, results []engine.UnifiedResult) (string, error) {
	data, _, err := a.engine.ExportResults(format, results)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
