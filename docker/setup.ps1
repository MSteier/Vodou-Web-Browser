# One-time setup for the Vodou backend bundle (Windows / PowerShell).
#   1. creates .env from .env.example (if missing)
#   2. writes a unique random secret_key into searxng/settings.yml
#   3. creates the noVNC viewer's LAN password (random per install, shown
#      once) or replaces the old published default -- see README.md
#
# Run from this folder:  ./setup.ps1
# Then:  docker compose up -d          (search only)
#        docker compose --profile ai up -d   (search + AI summaries)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
} else {
    Write-Host ".env already exists — leaving it as is"
}

$settings = Join-Path $PSScriptRoot "searxng/settings.yml"
$text = Get-Content $settings -Raw
if ($text -match "__REPLACE_WITH_RANDOM_SECRET__") {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $text = $text -replace "__REPLACE_WITH_RANDOM_SECRET__", $secret
    Set-Content -Path $settings -Value $text -NoNewline
    Write-Host "Wrote a unique secret_key into searxng/settings.yml"
} else {
    Write-Host "secret_key already set — leaving it as is"
}

# Viewer LAN password: generated here, on the host, never at image build time.
# Only its hash is stored, in a host file that survives `docker compose
# down/up`. Re-running is safe: an existing password is kept, and an install
# still on the old published default gets a new random one.
$htpasswd = $env:VODOU_VIEWER_HTPASSWD
if (-not $htpasswd -and (Test-Path ".env")) {
    $line = Select-String -Path ".env" -Pattern '^VODOU_VIEWER_HTPASSWD=(.*)$' |
        Select-Object -Last 1
    if ($line) { $htpasswd = $line.Matches[0].Groups[1].Value.Trim().Trim('"') }
}
$python = $null
foreach ($candidate in "python", "py", "python3") {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { $python = $cmd.Source; break }
}
if (-not $python) {
    Write-Host "WARNING: Python not found, so the viewer LAN password was not set up."
    Write-Host "         Install Python, then run:  python manage_viewer_password.py seed"
} else {
    $viewerArgs = @("manage_viewer_password.py")
    if ($htpasswd) { $viewerArgs += @("--file", $htpasswd) }
    $viewerArgs += "seed"
    & $python @viewerArgs
    if ($LASTEXITCODE -ne 0) { throw "Setting up the viewer LAN password failed." }
}

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  docker compose up -d                  # search only"
Write-Host "  docker compose --profile ai up -d     # search + AI summaries"
Write-Host ""
Write-Host "Then open Vodou — it defaults to https://localhost/searxng"
