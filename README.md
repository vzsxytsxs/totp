# Authenticator

Autenticador de dois fatores (2FA) para **Android** e **Windows**, no estilo do
Google Authenticator. Funciona 100% offline: não tem sincronização, conta online,
anúncios nem telemetria. No Android o app nem tem permissão de internet.

| | Android | Windows |
|---|---|---|
| Linguagem | Kotlin + Jetpack Compose | Rust + Slint |
| Adicionar por QR code | câmera ou print/foto da galeria | print colado (Ctrl+V), arquivo de imagem ou "escanear tela" |
| Adicionar por texto | chave de configuração ou link `otpauth://` | chave de configuração ou link `otpauth://` |
| Importar do Google Authenticator | sim (QR de "Transferir contas") | sim (QR de "Transferir contas") |
| Exportar | QR codes no formato do Google Authenticator ou arquivo de backup com senha | igual |
| Bloqueio | digital, rosto ou PIN/padrão/senha do celular | PIN ou senha próprio do app |

Os dois apps leem o mesmo arquivo de backup, então dá para passar as contas do
celular para o PC e vice-versa. A interface dos apps está em inglês.

## Segurança

**Android**
- Sem permissão de internet (o próprio Android impede qualquer conexão; o CI confere isso a cada build).
- Contas guardadas criptografadas (AES-256-GCM) com uma chave que fica no Android Keystore, no hardware de segurança do celular quando ele tiver. Copiar o arquivo para outro aparelho não serve de nada.
- Bloqueio por biometria (digital/rosto) com alternativa pelo PIN, padrão ou senha do celular. Também pede autenticação para exportar e para desligar o bloqueio.
- Bloqueia prints e esconde os códigos na tela de apps recentes (pode ser desligado nas configurações).
- O código copiado é marcado como sensível e apagado da área de transferência após 30 s.
- Backup automático do Android e transferência entre aparelhos desativados para os segredos. Use o backup criptografado do próprio app.

**Windows**
- As contas ficam em `%APPDATA%\Authenticator\vault.dat`, protegidas em duas camadas:
  1. PIN/senha → Argon2id (64 MiB) → AES-256-GCM;
  2. por cima, a proteção de dados do Windows (DPAPI), que liga o arquivo ao seu usuário do Windows.
- Depois de 5 PINs errados o app passa a impor esperas cada vez maiores.
- Bloqueio automático por inatividade (1, 5, 15 ou 60 min, ou nunca) e bloqueio manual (Ctrl+L).
- A janela fica invisível para prints, gravação e compartilhamento de tela (pode ser desligado).
- O código copiado não entra no histórico da área de transferência (Win+V) nem na nuvem, e é apagado após 30 s.
- Leve: abre em uma fração de segundo e usa ~20 MB de RAM.

**Backup**: arquivo JSON com Argon2id + AES-256-GCM, documentado em
[docs/backup-format.md](docs/backup-format.md). Sem a senha não abre.

## Baixar

Cada push gera os executáveis no GitHub Actions:
**Actions → último "Build" → Artifacts**:

- `Authenticator-Windows` → `Authenticator.exe` (não precisa instalar; é só abrir)
- `Authenticator-Android` → `Authenticator.apk`

Ao criar uma tag `v1.0.0` (por exemplo), os dois arquivos também são publicados
em **Releases**.

- **Windows**: como o `.exe` não tem assinatura digital paga, o SmartScreen pode avisar. Clique em "Mais informações" → "Executar assim mesmo".
- **Android**: permita "instalar apps desconhecidos" para o navegador ou gerenciador de arquivos que abrir o APK. Precisa de Android 8.0 ou mais novo.

### Chave de assinatura do Android (importante)

O Android só instala uma **atualização** se ela for assinada com a mesma chave
da versão instalada. Sem uma chave sua, cada build do GitHub sai com uma chave
temporária diferente, e atualizar exigiria desinstalar o app, **perdendo as
contas**. Crie a chave uma vez, antes de começar a usar o app de verdade:

1. No PC (com o Android Studio instalado), rode `.\scripts\create-android-key.ps1`.
2. Ele cria `android\release.jks` e `android\keystore.properties`, que não vão para o git. **Guarde uma cópia do `release.jks` e da senha.**
3. Para o GitHub Actions usar a mesma chave, crie os secrets que o script mostra no final (Settings → Secrets and variables → Actions).

De qualquer forma, mantenha sempre um backup criptografado das contas (menu → **Export / transfer**).

## Como usar

### Trazer as contas do Google Authenticator

**Para o Android:**
1. No Google Authenticator: menu → **Transferir contas** → **Exportar contas** → escolha as contas.
2. No Authenticator: **+** → **Scan QR code** e aponte para o QR. Se forem vários QR codes, escaneie um de cada vez: o app avisa quantos faltam.

**Para o Windows:** o Google Authenticator bloqueia prints da tela de
exportação, então o caminho mais fácil é:
1. Importar no Android como acima.
2. No Android: menu (⋮) → **Export / transfer** → **Save backup file…** e envie o arquivo para o PC.
3. No Windows: **+** → **Restore from backup file…**.

Outra opção: tirar uma foto da tela do Google Authenticator com outro aparelho
e abrir a foto no Windows (**+** → **Open image file…**).

### Passar contas para outro aparelho

- **Arquivo de backup** (recomendado): leva todas as contas, inclusive as que o Google Authenticator não suporta (períodos diferentes de 30 s ou 7 dígitos).
- **QR codes**: menu → **Export / transfer** → **Show QR codes**. Funcionam no Google Authenticator, neste app e na maioria dos autenticadores. Quem vir esses QR codes pode copiar suas contas.

### Windows: atalhos

| Tecla | Ação |
|---|---|
| Ctrl+V | colar print de QR code (lista ou tela "Adicionar") |
| Ctrl+N | adicionar conta |
| Ctrl+L | bloquear |
| Esc | voltar |

Para pegar um QR que está na tela: **Win+Shift+S**, selecione o QR, volte ao app e aperte **Ctrl+V**. Ou use **Scan screen**.

**Esqueci o PIN do Windows**: não há como recuperar (é o que protege as contas).
Na tela de bloqueio, "Forgot your PIN?" apaga os dados do PC; depois restaure
de um backup.

## Compilar no seu PC

Os scripts ficam na raiz e em `scripts\`. Dá para dar dois cliques nos `.cmd`
ou rodar no terminal com opções.

### App do Windows

Requisitos (uma vez):
```powershell
winget install Rustlang.Rustup
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Compilar:
```powershell
.\build-windows.cmd            # gera dist\Authenticator.exe
.\build-windows.cmd -Test -Run # roda os testes, compila e abre
.\build-windows.cmd -Dev       # compilação rápida para testar mudanças
```

### App do Android

Requisito: [Android Studio](https://developer.android.com/studio) (abra uma vez
para ele baixar o SDK).

```powershell
.\build-android.cmd            # gera dist\Authenticator-debug.apk
.\build-android.cmd -Install   # compila e instala no celular conectado por USB (depuração USB ligada)
.\build-android.cmd -Release   # gera dist\Authenticator.apk assinado com a sua chave
```

A versão de teste (debug) se instala **ao lado** da versão normal, com o nome
"Authenticator (debug)", então testes nunca mexem nas suas contas reais.
Também dá para abrir a pasta `android\` direto no Android Studio.

### Testes

```powershell
cd windows; cargo test                 # Rust: RFC 4226/6238, importação, backup, cofre, QR
cd android; .\gradlew.bat -p core test # Kotlin: mesma lógica e mesmos vetores
```

Os dois conjuntos de testes usam os mesmos vetores em `docs/test-vectors/`,
incluindo um backup gerado por cada app, para garantir que um sempre abre o
backup do outro.

## Estrutura

```
windows/            App do Windows (Rust)
  src/              núcleo (otp, migration, backup, crypto, vault) + main.rs (interface)
  ui/app.slint      telas
android/
  core/             lógica em Kotlin puro (testada no PC, sem Android)
  app/              app Android (Compose, CameraX, Keystore, biometria)
docs/               formato do backup e vetores de teste compartilhados
scripts/            scripts de compilação para o Windows
.github/workflows/  CI: compila e testa os dois apps
```

## Créditos

Interface do Windows feita com [Slint](https://slint.dev). Ícones Material Design
(Apache 2.0). Leitura de QR no Android com ZXing (Apache 2.0) e no Windows com
rqrr. Argon2 no Android pelo Bouncy Castle; criptografia no Windows pelos crates
RustCrypto.
