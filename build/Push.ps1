# VaultaX NuGet Push Script
# Usage: .\Push.ps1
# Requires: $Env:NUGET_API_KEY to be set

$ErrorActionPreference = "Stop"

Write-Host "VaultaX NuGet Push Script" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# Configuration
$artifactsPath = Join-Path $PSScriptRoot "..\artifacts"
$nugetSource = if ($Env:NUGET_URL) { $Env:NUGET_URL } else { "https://api.nuget.org/v3/index.json" }

# Validate API key
if (-not $Env:NUGET_API_KEY) {
    Write-Host "Error: NUGET_API_KEY environment variable is not set" -ForegroundColor Red
    Write-Host "Set it using: `$Env:NUGET_API_KEY = 'your-api-key'" -ForegroundColor Yellow
    exit 1
}

# Validate artifacts folder
if (-not (Test-Path $artifactsPath)) {
    Write-Host "Error: Artifacts folder not found at $artifactsPath" -ForegroundColor Red
    Write-Host "Run Build.ps1 first to create packages" -ForegroundColor Yellow
    exit 1
}

# Get all packages
$packages = Get-ChildItem $artifactsPath -Filter "*.nupkg" | Where-Object { $_.Name -notlike "*.snupkg" }

if ($packages.Count -eq 0) {
    Write-Host "Error: No .nupkg files found in $artifactsPath" -ForegroundColor Red
    exit 1
}

Write-Host "`nPushing packages to: $nugetSource" -ForegroundColor Yellow
Write-Host "Found $($packages.Count) package(s) to push:`n" -ForegroundColor Gray

foreach ($package in $packages) {
    Write-Host "  Pushing $($package.Name)..." -ForegroundColor Gray
    dotnet nuget push $package.FullName --source $nugetSource --api-key $Env:NUGET_API_KEY --skip-duplicate
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    Warning: Push may have failed for $($package.Name)" -ForegroundColor Yellow
    } else {
        Write-Host "    Done!" -ForegroundColor Green
    }
}

Write-Host "`nPush completed!" -ForegroundColor Green
