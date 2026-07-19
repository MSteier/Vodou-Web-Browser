# One-time setup for the Vodou backend bundle (Windows / PowerShell).
#   1. creates .env from .env.example (if missing)
#   2. writes a unique random secret_key into searxng/settings.yml
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

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  docker compose up -d                  # search only"
Write-Host "  docker compose --profile ai up -d     # search + AI summaries"
Write-Host ""
Write-Host "Then open Vodou — it defaults to https://localhost/searxng"
