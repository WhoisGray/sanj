package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSameRelease(t *testing.T) {
	if !sameRelease("v1.0.1", "v1.0.1") || !sameRelease("1.0.1", "v1.0.1") {
		t.Fatal("same tag should match")
	}
	if sameRelease("dev", "v1.0.1") || sameRelease("v1.0.0", "v1.0.1") || sameRelease("", "v1.0.1") {
		t.Fatal("different or dev versions should not match")
	}
}

func TestReleaseAssetName(t *testing.T) {
	name, err := releaseAssetName("v1.0.1", "darwin", "arm64")
	if err != nil || name != "sanj_1.0.1_darwin_arm64.tar.gz" {
		t.Fatalf("darwin: %s %v", name, err)
	}
	name, err = releaseAssetName("v1.0.1", "windows", "amd64")
	if err != nil || name != "sanj_1.0.1_windows_amd64.zip" {
		t.Fatalf("windows: %s %v", name, err)
	}
	if _, err := releaseAssetName("v1.0.1", "linux", "386"); err == nil {
		t.Fatal("expected unsupported arch")
	}
}

func TestChecksumFor(t *testing.T) {
	text := "abc\n" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  sanj_1.0.1_linux_amd64.tar.gz\n" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa *sanj_1.0.1_windows_amd64.zip\n"
	got, err := checksumFor(text, "sanj_1.0.1_windows_amd64.zip")
	if err != nil || got != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := checksumFor(text, "missing"); err == nil {
		t.Fatal("expected missing checksum")
	}
}

func TestUpdateExecutable(t *testing.T) {
	payload := []byte("#!/bin/sh\necho v1.0.1\n")
	name, archive := packRelease(t, payload)
	sum := sha256.Sum256(archive)
	checksums := hex.EncodeToString(sum[:]) + "  " + name + "\n"

	mux := http.NewServeMux()
	var assetHits int
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		rel := ghRelease{
			TagName: "v1.0.1",
			Assets: []ghAsset{
				{Name: name, URL: "http://" + r.Host + "/asset"},
				{Name: "checksums.txt", URL: "http://" + r.Host + "/checksums.txt"},
			},
		}
		json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) {
		assetHits++
		w.Write(archive)
	})
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksums))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	old := version
	t.Cleanup(func() { version = old })

	version = "v1.0.1"
	exe := filepath.Join(t.TempDir(), "sanj")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := updateExecutable(exe, srv.URL+"/latest"); err != nil {
		t.Fatal(err)
	}
	if assetHits != 0 {
		t.Fatalf("already latest still downloaded %d assets", assetHits)
	}
	body, err := os.ReadFile(exe)
	if err != nil || string(body) != "old" {
		t.Fatalf("binary changed: %q %v", body, err)
	}

	version = "v1.0.0"
	if err := updateExecutable(exe, srv.URL+"/latest"); err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(exe)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("replaced with %q %v", body, err)
	}
	info, err := os.Stat(exe)
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("mode %v %v", info, err)
	}

	name2, archive2 := packTagged(t, "v9.9.9", payload)
	bad2 := "0000000000000000000000000000000000000000000000000000000000000000  " + name2 + "\n"
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ghRelease{
			TagName: "v9.9.9",
			Assets: []ghAsset{
				{Name: name2, URL: "http://" + r.Host + "/asset"},
				{Name: "checksums.txt", URL: "http://" + r.Host + "/checksums.txt"},
			},
		})
	})
	mux2.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) { w.Write(archive2) })
	mux2.HandleFunc("/checksums.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(bad2)) })
	srv2 := httptest.NewServer(mux2)
	t.Cleanup(srv2.Close)
	if err := updateExecutable(exe, srv2.URL+"/latest"); err == nil {
		t.Fatal("expected checksum mismatch")
	}
	body, err = os.ReadFile(exe)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("checksum failure changed the binary: %q %v", body, err)
	}
}

func packRelease(t *testing.T, payload []byte) (string, []byte) {
	t.Helper()
	return packTagged(t, "v1.0.1", payload)
}

func packTagged(t *testing.T, tag string, payload []byte) (string, []byte) {
	t.Helper()
	name, err := releaseAssetName(tag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	member := "sanj"
	if runtime.GOOS == "windows" {
		member = "sanj.exe"
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return name, buf.Bytes()
	}
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return name, buf.Bytes()
}
