# VaultaX Build Script
# Usage: .\Build.ps1

$ErrorActionPreference = "Stop"

Write-Host "VaultaX Build Script" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan

# Configuration
$solutionPath = Join-Path $PSScriptRoot "..\VaultaX.sln"
$artifactsPath = Join-Path $PSScriptRoot "..\artifacts"
$configuration = "Release"

# Clean
Write-Host "`n[1/4] Cleaning..." -ForegroundColor Yellow
dotnet clean $solutionPath -c $configuration --verbosity minimal
if ($LASTEXITCODE -ne 0) { throw "Clean failed" }

# Restore
Write-Host "`n[2/4] Restoring packages..." -ForegroundColor Yellow
dotnet restore $solutionPath
if ($LASTEXITCODE -ne 0) { throw "Restore failed" }

# Build
Write-Host "`n[3/4] Building..." -ForegroundColor Yellow
dotnet build $solutionPath -c $configuration --no-restore
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

# Test
Write-Host "`n[4/4] Running tests..." -ForegroundColor Yellow
dotnet test $solutionPath -c $configuration --no-build --verbosity normal
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

# Pack
Write-Host "`n[5/5] Creating NuGet packages..." -ForegroundColor Yellow

# Clean artifacts folder
if (Test-Path $artifactsPath) {
    Remove-Item $artifactsPath -Recurse -Force
}
New-Item -ItemType Directory -Path $artifactsPath -Force | Out-Null

# Pack the main project
$projectPath = Join-Path $PSScriptRoot "..\src\VaultaX\VaultaX.csproj"
Write-Host "  Packing VaultaX..." -ForegroundColor Gray
dotnet pack $projectPath -c $configuration -o $artifactsPath --no-build
if ($LASTEXITCODE -ne 0) { throw "Pack failed" }

Write-Host "`nBuild completed successfully!" -ForegroundColor Green
Write-Host "Packages created in: $artifactsPath" -ForegroundColor Green

# List created packages
Write-Host "`nCreated packages:" -ForegroundColor Cyan
Get-ChildItem $artifactsPath -Filter "*.nupkg" | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
