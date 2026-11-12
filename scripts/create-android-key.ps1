<#
.SYNOPSIS
  Cria a chave que assina o APK do Android. Faca isso UMA vez e guarde a chave.
  O Android so instala atualizacoes assinadas com a mesma chave: se a chave
  for perdida, sera preciso desinstalar o app (exporte um backup antes!).
#>
param([string]$Alias = "authenticator")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$android = Join-Path $root "android"
$keystore = Join-Path $android "release.jks"

if (Test-Path $keystore) {
    Write-Host "Ja existe uma chave em $keystore. Nada foi alterado." -ForegroundColor Yellow
    exit 1
}

$keytool = @(
    "$env:JAVA_HOME\bin\keytool.exe",
    "$env:ProgramFiles\Android\Android Studio\jbr\bin\keytool.exe",
    "$env:LOCALAPPDATA\Programs\Android Studio\jbr\bin\keytool.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $keytool) { $keytool = (Get-Command keytool -ErrorAction SilentlyContinue).Source }
if (-not $keytool) { throw "keytool nao encontrado. Instale o Android Studio ou um JDK 17." }

function Read-Plain([string]$prompt) {
    $secure = Read-Host $prompt -AsSecureString
    return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
$password = Read-Plain "Senha para a chave (minimo 8 caracteres)"
if ($password.Length -lt 8) { throw "A senha precisa ter pelo menos 8 caracteres." }
if ($password -ne (Read-Plain "Repita a senha")) { throw "As senhas nao conferem." }

& $keytool -genkeypair -keystore $keystore -storetype PKCS12 -alias $Alias -keyalg RSA -keysize 4096 `
    -validity 36500 -storepass $password -keypass $password -dname "CN=Authenticator"
if ($LASTEXITCODE -ne 0) { throw "keytool falhou." }

@"
storeFile=release.jks
storePassword=$password
keyAlias=$Alias
keyPassword=$password
"@ | Set-Content -Encoding ASCII (Join-Path $android "keystore.properties")

$b64File = Join-Path $android "release.jks.base64.txt"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($keystore)) | Set-Content -Encoding ASCII $b64File

Write-Host ""
Write-Host "Chave criada: $keystore" -ForegroundColor Green
Write-Host "Esses arquivos NAO vao para o git (.gitignore). Guarde uma copia de release.jks e da senha em local seguro."
Write-Host ""
Write-Host "Para o GitHub Actions assinar o APK, crie estes secrets em" -ForegroundColor Cyan
Write-Host "  GitHub > repositorio > Settings > Secrets and variables > Actions > New repository secret:"
Write-Host "  ANDROID_KEYSTORE_BASE64   = conteudo do arquivo $b64File"
Write-Host "  ANDROID_KEYSTORE_PASSWORD = a senha"
Write-Host "  ANDROID_KEY_ALIAS         = $Alias"
Write-Host "  ANDROID_KEY_PASSWORD      = a senha"
Write-Host "Depois de criar os secrets, apague $b64File."
