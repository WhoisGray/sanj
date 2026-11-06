#!/bin/sh
# Install the latest sanj release. -update does the same install again.
set -eu

repo="WhoisGray/sanj"
update=0
for arg in "$@"; do
  case "$arg" in
    -update|--update) update=1 ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux) goos=linux ;;
  darwin) goos=darwin ;;
  *)
    echo "use PowerShell on Windows: irm https://raw.githubusercontent.com/${repo}/refs/heads/main/install.ps1 | iex" >&2
    exit 1
    ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

api="https://api.github.com/repos/${repo}/releases/latest"
json=$(curl -fsSL -A sanj-install -H "Accept: application/vnd.github+json" "$api") || {
  echo "could not read the latest release" >&2
  exit 1
}
# GitHub returns the release on one line, so tag_name is not at the start of a line.
tag=$(printf '%s\n' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
case "$tag" in
  v[0-9]*) ;;
  *)
    echo "unexpected release tag: ${tag:-<empty>}" >&2
    exit 1
    ;;
esac
ver=${tag#v}

if command -v sanj >/dev/null 2>&1; then
  current=$(sanj -version 2>/dev/null || true)
  if [ "$current" = "$tag" ]; then
    echo "sanj ${tag} is already the latest"
    exit 0
  fi
fi

asset="sanj_${ver}_${goos}_${goarch}.tar.gz"
base="https://github.com/${repo}/releases/download/${tag}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -A sanj-install -o "$tmp/$asset" "$base/$asset" || {
  echo "download failed: $base/$asset" >&2
  exit 1
}
curl -fsSL -A sanj-install -o "$tmp/checksums.txt" "$base/checksums.txt" || {
  echo "download failed: $base/checksums.txt" >&2
  exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi
want=$(awk -v name="$asset" '{ f = $NF; sub(/^\*/, "", f); if (f == name) { print $1; exit } }' "$tmp/checksums.txt")
got=$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')
want=$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')
if [ -z "$want" ] || [ "$got" != "$want" ]; then
  echo "checksum mismatch for $asset" >&2
  exit 1
fi

tar -xzf "$tmp/$asset" -C "$tmp" sanj
chmod 755 "$tmp/sanj"

if command -v sanj >/dev/null 2>&1; then
  dest=$(command -v sanj)
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  dest=/usr/local/bin/sanj
else
  mkdir -p "${HOME}/.local/bin"
  dest="${HOME}/.local/bin/sanj"
fi

dest_dir=$(dirname "$dest")
if [ -w "$dest_dir" ] && { [ ! -e "$dest" ] || [ -w "$dest" ]; }; then
  mv "$tmp/sanj" "$dest"
else
  sudo mv "$tmp/sanj" "$dest"
  sudo chmod 755 "$dest"
fi
chmod 755 "$dest" 2>/dev/null || true

if [ "$goos" = "darwin" ]; then
  xattr -d com.apple.quarantine "$dest" 2>/dev/null || true
fi

if [ "$update" -eq 1 ]; then
  echo "updated ${dest} to ${tag}"
else
  echo "installed ${tag} to ${dest}"
fi
case ":${PATH}:" in
  *":${dest_dir}:"*) ;;
  *) echo "add this to your shell profile: export PATH=\"${dest_dir}:\$PATH\"" ;;
esac
"$dest" -version
