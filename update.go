package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	releaseAPI      = "https://api.github.com/repos/WhoisGray/vpnban/releases/latest"
	maxReleaseBytes = 64 << 20
)

var updateClient = &http.Client{Timeout: 2 * time.Minute}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func selfUpdate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return updateExecutable(exe, releaseAPI)
}

func updateExecutable(exe, api string) error {
	body, err := getBytes(api, 1<<20, "application/vnd.github+json")
	if err != nil {
		return fmt.Errorf("latest release: %w", err)
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return fmt.Errorf("latest release: %w", err)
	}
	if rel.TagName == "" {
		return fmt.Errorf("latest release has no tag")
	}
	if sameRelease(version, rel.TagName) {
		fmt.Printf("vpnban %s is already the latest\n", rel.TagName)
		return nil
	}
	name, err := releaseAssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	asset := rel.find(name)
	sums := rel.find("checksums.txt")
	if asset == nil || sums == nil {
		return fmt.Errorf("release %s has no %s", rel.TagName, name)
	}
	archive, err := getBytes(asset.URL, maxReleaseBytes, "")
	if err != nil {
		return err
	}
	sumText, err := getBytes(sums.URL, 1<<20, "")
	if err != nil {
		return err
	}
	want, err := checksumFor(string(sumText), name)
	if err != nil {
		return err
	}
	got := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(got[:]), want) {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	bin, err := extractBinary(name, archive)
	if err != nil {
		return err
	}
	if err := replaceExecutable(exe, bin); err != nil {
		return err
	}
	fmt.Printf("updated %s to %s\n", exe, rel.TagName)
	return nil
}

func (r ghRelease) find(name string) *ghAsset {
	for i := range r.Assets {
		if r.Assets[i].Name == name && r.Assets[i].URL != "" {
			return &r.Assets[i]
		}
	}
	return nil
}

func sameRelease(current, tag string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	tag = strings.TrimPrefix(strings.TrimSpace(tag), "v")
	return current != "" && current != "dev" && current == tag
}

func releaseAssetName(tag, goos, goarch string) (string, error) {
	ver := strings.TrimPrefix(strings.TrimSpace(tag), "v")
	if ver == "" {
		return "", fmt.Errorf("empty release tag")
	}
	switch goos {
	case "linux", "darwin", "windows":
	default:
		return "", fmt.Errorf("unsupported OS %s", goos)
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("unsupported architecture %s", goarch)
	}
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("vpnban_%s_%s_%s%s", ver, goos, goarch, ext), nil
}

func checksumFor(text, name string) (string, error) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		file := strings.TrimPrefix(fields[len(fields)-1], "*")
		if file != name {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != 64 {
			return "", fmt.Errorf("bad checksum for %s", name)
		}
		return sum, nil
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

func extractBinary(archiveName string, data []byte) ([]byte, error) {
	want := "vpnban"
	if strings.HasSuffix(archiveName, ".zip") {
		want = "vpnban.exe"
		return unzipOne(data, want)
	}
	return untarOne(data, want)
}

func memberName(name string) string {
	name = strings.TrimPrefix(name, "./")
	return name
}

func untarOne(data []byte, want string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if memberName(hdr.Name) != want || hdr.Typeflag != tar.TypeReg {
			continue
		}
		return readLimited(tr, maxReleaseBytes)
	}
	return nil, fmt.Errorf("archive has no %s", want)
}

func unzipOne(data []byte, want string) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range r.File {
		if memberName(f.Name) != want || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := readLimited(rc, maxReleaseBytes)
		rc.Close()
		return body, err
	}
	return nil, fmt.Errorf("archive has no %s", want)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("release file is larger than %dMB", limit>>20)
	}
	return b, nil
}

func getBytes(url string, limit int64, accept string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpnban/"+strings.TrimSpace(version))
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := updateClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 180 {
			msg = msg[:180]
		}
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("GET %s: %s", url, msg)
	}
	return body, nil
}

func replaceExecutable(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vpnban-new-*")
	if err != nil {
		return fmt.Errorf("cannot replace %s: %w; run with permission to write that file", path, err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// shortcut: Windows locks the running exe, so the previous file stays as vpnban.exe.old until the next update removes it.
		old := path + ".old"
		os.Remove(old)
		if err := os.Rename(path, old); err != nil {
			return err
		}
		if err := os.Rename(tmpName, path); err != nil {
			os.Rename(old, path)
			return err
		}
		ok = true
		return nil
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
