<#
.SYNOPSIS
  Compila o app do Windows e copia para dist\Authenticator.exe.
.EXAMPLE
  .\scripts\build-windows.ps1            # compila (release, otimizado)
  .\scripts\build-windows.ps1 -Test      # roda os testes antes
  .\scripts\build-windows.ps1 -Run       # abre o app no final
  .\scripts\build-windows.ps1 -Dev       # compilação rápida (debug) para testes
#>
param(
    [switch]$Test,
    [switch]$Run,
    [switch]$Dev
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Rust nao foi encontrado." -ForegroundColor Yellow
    Write-Host "1) Instale o Rust:        winget install Rustlang.Rustup   (ou https://rustup.rs)"
    Write-Host "2) Instale o compilador C++ da Microsoft (necessario para o Rust no Windows):"
    Write-Host "   winget install Microsoft.VisualStudio.2022.BuildTools --override `"--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended`""
    Write-Host "Depois feche e abra o terminal e rode este script de novo."
    exit 1
}

Push-Location (Join-Path $root "windows")
try {
    if ($Test) {
        Write-Host "Rodando testes..." -ForegroundColor Cyan
        cargo test --release
        if ($LASTEXITCODE -ne 0) { throw "Os testes falharam." }
    }
    $mode = if ($Dev) { "debug" } else { "release" }
    Write-Host "Compilando ($mode)..." -ForegroundColor Cyan
    if ($Dev) { cargo build } else { cargo build --release }
    if ($LASTEXITCODE -ne 0) { throw "A compilacao falhou." }

    $dist = Join-Path $root "dist"
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $exe = Join-Path $dist "Authenticator.exe"
    try {
        Copy-Item "target\$mode\authenticator.exe" $exe -Force
    } catch {
        throw "Nao foi possivel substituir $exe. Feche o Authenticator se ele estiver aberto e tente de novo."
    }
    Write-Host "Pronto: $exe" -ForegroundColor Green
    if ($Run) { Start-Process $exe }
} finally {
    Pop-Location
}
