$ErrorActionPreference = "Stop"

# Install or update the hardened fork from its latest GitHub release.
# Re-run the same command whenever a new fork release is published.
$Repo = "syaifulizhan/codebase-memory-mcp"
$Branch = "hoki-fork"
$InstallerUri = "https://raw.githubusercontent.com/$Repo/$Branch/install.ps1"
$DownloadBase = "https://github.com/$Repo/releases/latest/download"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cbm-fork-" + [guid]::NewGuid().ToString("N"))
$InstallerPath = Join-Path $TempDir "install.ps1"

New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
try {
    $Curl = Get-Command curl.exe -ErrorAction Stop
    & $Curl.Source -fSL --proto "=https" --proto-redir "=https" $InstallerUri -o $InstallerPath
    if ($LASTEXITCODE -ne 0) {
        throw "could not download the fork installer (curl exit $LASTEXITCODE)"
    }
    $PreviousDownloadUrl = $env:CBM_DOWNLOAD_URL
    $env:CBM_DOWNLOAD_URL = $DownloadBase
    try {
        & $InstallerPath @args
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    } finally {
        if ($null -eq $PreviousDownloadUrl) {
            Remove-Item Env:CBM_DOWNLOAD_URL -ErrorAction SilentlyContinue
        } else {
            $env:CBM_DOWNLOAD_URL = $PreviousDownloadUrl
        }
    }
} finally {
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
