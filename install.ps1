# Install the latest sanj release. Run again, or use: sanj -update
& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $repo = 'WhoisGray/sanj'

  switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
  }

  $api = "https://api.github.com/repos/$repo/releases/latest"
  $rel = Invoke-RestMethod -Headers @{ 'User-Agent' = 'sanj-install'; Accept = 'application/vnd.github+json' } -Uri $api
  $tag = [string]$rel.tag_name
  if ($tag -notmatch '^v[0-9]') { throw "unexpected release tag: $tag" }
  $ver = $tag.Substring(1)

  $existing = Get-Command sanj -ErrorAction SilentlyContinue
  if ($existing -and (& $existing.Source -version) -eq $tag) {
    Write-Output "sanj $tag is already the latest"
    return
  }

  $name = "sanj_${ver}_windows_${arch}.zip"
  $base = "https://github.com/$repo/releases/download/$tag"
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sanj-install-" + [guid]::NewGuid().ToString('n'))
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  try {
    Invoke-WebRequest -Headers @{ 'User-Agent' = 'sanj-install' } -Uri "$base/$name" -OutFile (Join-Path $tmp $name) -UseBasicParsing
    Invoke-WebRequest -Headers @{ 'User-Agent' = 'sanj-install' } -Uri "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt') -UseBasicParsing
    $want = $null
    foreach ($line in Get-Content (Join-Path $tmp 'checksums.txt')) {
      $parts = $line -split '\s+'
      if ($parts.Length -ge 2 -and $parts[-1].TrimStart('*') -eq $name) { $want = $parts[0] }
    }
    $got = (Get-FileHash (Join-Path $tmp $name) -Algorithm SHA256).Hash
    if (-not $want -or $got.ToLowerInvariant() -ne $want.ToLowerInvariant()) {
      throw "checksum mismatch for $name"
    }
    Expand-Archive -Path (Join-Path $tmp $name) -DestinationPath $tmp -Force
    $bin = Join-Path $tmp 'sanj.exe'
    if (-not (Test-Path $bin)) { throw 'archive has no sanj.exe' }

    if ($existing) {
      $dest = $existing.Source
      # shortcut: Windows locks a running exe, so move it aside before copy. The .old file is removed on the next update.
      $old = "$dest.old"
      if (Test-Path $old) { Remove-Item -Force $old }
      if (Test-Path $dest) { Rename-Item -Force $dest $old }
    } else {
      $destDir = Join-Path $env:LOCALAPPDATA 'sanj'
      New-Item -ItemType Directory -Force -Path $destDir | Out-Null
      $dest = Join-Path $destDir 'sanj.exe'
      $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
      if (-not $userPath) { $userPath = '' }
      $pieces = @($userPath -split ';' | Where-Object { $_ -ne '' })
      $found = $false
      foreach ($piece in $pieces) {
        if ($piece.TrimEnd('\') -eq $destDir) { $found = $true }
      }
      if (-not $found) {
        $joined = (@($pieces) + $destDir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $joined, 'User')
        $env:Path = $env:Path + ';' + $destDir
        Write-Output "added $destDir to your user PATH; open a new terminal"
      }
    }
    Copy-Item -Force $bin $dest
    Write-Output "installed $tag to $dest"
    & $dest -version
  } finally {
    Remove-Item -Recurse -Force $tmp
  }
}
