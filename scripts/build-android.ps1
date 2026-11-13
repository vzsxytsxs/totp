<#
.SYNOPSIS
  Compila o APK do Android e copia para a pasta dist\.
  Precisa do Android Studio instalado (ele traz o Java e o Android SDK).
.EXAMPLE
  .\scripts\build-android.ps1              # APK de teste (debug), instala ao lado da versao normal
  .\scripts\build-android.ps1 -Install     # compila e instala no celular conectado por USB
  .\scripts\build-android.ps1 -Release     # APK final (assinado com a sua chave, se existir)
#>
param(
    [switch]$Release,
    [switch]$Install,
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$android = Join-Path $root "android"

# Java 17+: JAVA_HOME ou o Java que vem com o Android Studio.
if (-not ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\java.exe"))) {
    $jbr = @(
        "$env:ProgramFiles\Android\Android Studio\jbr",
        "$env:LOCALAPPDATA\Programs\Android Studio\jbr",
        "${env:ProgramFiles(x86)}\Android\Android Studio\jbr"
    ) | Where-Object { Test-Path "$_\bin\java.exe" } | Select-Object -First 1
    if ($jbr) {
        $env:JAVA_HOME = $jbr
    } elseif (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Write-Host "Java nao encontrado. Instale o Android Studio (https://developer.android.com/studio)" -ForegroundColor Yellow
        Write-Host "ou o JDK 17:  winget install EclipseAdoptium.Temurin.17.JDK"
        exit 1
    }
}

# Android SDK.
$sdk = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, "$env:LOCALAPPDATA\Android\Sdk") |
    Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $sdk) {
    Write-Host "Android SDK nao encontrado." -ForegroundColor Yellow
    Write-Host "Instale o Android Studio e abra-o uma vez para ele baixar o SDK, ou defina ANDROID_HOME."
    exit 1
}
"sdk.dir=" + ($sdk -replace '\\', '/') | Set-Content -Encoding ASCII (Join-Path $android "local.properties")

Push-Location $android
try {
    if (-not $SkipTests) {
        Write-Host "Rodando testes..." -ForegroundColor Cyan
        .\gradlew.bat -p core test
        if ($LASTEXITCODE -ne 0) { throw "Os testes falharam." }
    }
    $variant = if ($Release) { "release" } else { "debug" }
    Write-Host "Compilando APK ($variant)..." -ForegroundColor Cyan
    .\gradlew.bat ":app:assemble$((Get-Culture).TextInfo.ToTitleCase($variant))"
    if ($LASTEXITCODE -ne 0) { throw "A compilacao falhou." }

    $dist = Join-Path $root "dist"
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $name = if ($Release) { "Authenticator.apk" } else { "Authenticator-debug.apk" }
    $apk = Join-Path $dist $name
    Copy-Item "app\build\outputs\apk\$variant\app-$variant.apk" $apk -Force
    Write-Host "Pronto: $apk" -ForegroundColor Green
    if ($Release -and -not (Test-Path (Join-Path $android "keystore.properties"))) {
        Write-Host "Aviso: sem chave propria (keystore.properties) o APK foi assinado com a chave de teste." -ForegroundColor Yellow
        Write-Host "Rode .\scripts\create-android-key.ps1 antes de instalar a versao definitiva."
    }

    if ($Install) {
        $adb = Join-Path $sdk "platform-tools\adb.exe"
        if (-not (Test-Path $adb)) { throw "adb nao encontrado em $adb" }
        Write-Host "Instalando no celular (ative a Depuracao USB)..." -ForegroundColor Cyan
        & $adb install -r $apk
        if ($LASTEXITCODE -ne 0) { throw "A instalacao falhou." }
    }
} finally {
    Pop-Location
}
