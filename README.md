# Authenticator

Autenticador de dois fatores (2FA) e gerenciador de senhas para **Android** e
**Windows**. Funciona 100% offline: não tem sincronização, conta online,
anúncios nem telemetria. No Android o app nem tem permissão de internet.

| | Android | Windows |
|---|---|---|
| Linguagem | Kotlin + Jetpack Compose | Rust + Slint |
| Visual | app de celular, abas "2FA codes" e "Passwords" | janela de desktop no estilo do KeePassXC: menus, barra lateral, tabela e painel de detalhes |
| Adicionar 2FA por QR code | câmera ou print/foto da galeria | print colado (Ctrl+V), arquivo de imagem ou "escanear tela" |
| Adicionar 2FA por texto | chave de configuração ou link `otpauth://` | chave de configuração ou link `otpauth://` |
| Importar do Google Authenticator | sim (QR de "Transferir contas") | sim (QR de "Transferir contas") |
| Senhas | lista, adicionar, ver e editar, gerador, ligar a um código 2FA | o mesmo + importar CSV do navegador + extensão que preenche no navegador |
| Exportar | QR de um código só, QR no formato do Google Authenticator ou backup com senha, escolhendo o que entra | igual |
| Bloqueio | digital, rosto ou PIN/padrão/senha do celular | PIN ou senha próprio do app |
| Extras | — | fica na área de notificação, inicia com o Windows, bloqueia junto com o Windows |

Os dois apps leem o mesmo arquivo de backup, então dá para passar códigos e
senhas do celular para o PC e vice-versa. A interface dos apps está em inglês.

## Segurança

**Android**
- Sem permissão de internet (o próprio Android impede qualquer conexão; o CI confere isso a cada build).
- Códigos e senhas guardados criptografados (AES-256-GCM) com uma chave que fica no Android Keystore, no hardware de segurança do celular quando ele tiver. Copiar o arquivo para outro aparelho não serve de nada.
- Bloqueio por biometria (digital/rosto) com alternativa pelo PIN, padrão ou senha do celular. Também pede autenticação para exportar e para desligar o bloqueio.
- Bloqueia prints e esconde os códigos na tela de apps recentes (pode ser desligado nas configurações).
- O código ou senha copiado é marcado como sensível e apagado da área de transferência após 30 s.
- Backup automático do Android e transferência entre aparelhos desativados para os segredos. Use o backup criptografado do próprio app.

**Windows**
- Códigos e senhas ficam em `%APPDATA%\Authenticator\vault.dat`, protegidos em duas camadas:
  1. PIN/senha → Argon2id (64 MiB) → AES-256-GCM;
  2. por cima, a proteção de dados do Windows (DPAPI), que liga o arquivo ao seu usuário do Windows.
- Depois de 5 PINs errados o app passa a impor esperas cada vez maiores.
- Bloqueio automático por inatividade (1, 5, 15 ou 60 min, ou nunca), bloqueio manual (Ctrl+L) e quando o Windows bloqueia ou entra em suspensão.
- Mostrar o QR de um código ou exportar pede o PIN de novo.
- A janela fica invisível para prints, gravação e compartilhamento de tela (pode ser desligado).
- O que é copiado não entra no histórico da área de transferência (Win+V) nem na nuvem, e é apagado após 30 s.
- Leve: abre em uma fração de segundo e usa ~20 MB de RAM.

**Extensão do navegador**: conversa só com o app no mesmo PC (native messaging
+ pipe local do Windows), nunca pela internet. É pareada uma vez com um código
que você confirma no app, e cada mensagem é criptografada. Só entrega uma senha
com o app desbloqueado e só para o site certo (o domínio da página tem que
bater com o site salvo). Detalhes em [docs/browser-protocol.md](docs/browser-protocol.md).

**Backup**: arquivo JSON com Argon2id + AES-256-GCM, documentado em
[docs/backup-format.md](docs/backup-format.md). Sem a senha não abre.

## Baixar

Cada push gera os executáveis no GitHub Actions:
**Actions → último "Build" → Artifacts**:

- `Authenticator-Windows` → `Authenticator.exe` (não precisa instalar; é só abrir)
- `Authenticator-Android` → `Authenticator.apk`

As versões prontas ficam em **Releases** (por exemplo `v2.0.0`).

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

De qualquer forma, mantenha sempre um backup criptografado (menu → **Export / transfer**).

## Como usar

### Trazer as contas do Google Authenticator

**Para o Android:**
1. No Google Authenticator: menu → **Transferir contas** → **Exportar contas** → escolha as contas.
2. No Authenticator: **+** → **Scan QR code** e aponte para o QR. Se forem vários QR codes, escaneie um de cada vez: o app avisa quantos faltam.

**Para o Windows:** o Google Authenticator bloqueia prints da tela de
exportação, então o caminho mais fácil é:
1. Importar no Android como acima.
2. No Android: menu (⋮) → **Export / transfer** → **Save backup file…** e envie o arquivo para o PC.
3. No Windows: **File** → **Restore backup…**.

Outra opção: tirar uma foto da tela do Google Authenticator com outro aparelho
e abrir a foto no Windows (**Tools** → **Open QR code image…**).

### Passar códigos e senhas para outro aparelho

- **Arquivo de backup** (recomendado): leva códigos e senhas, inclusive códigos que o Google Authenticator não suporta (períodos diferentes de 30 s ou 7 dígitos). Restaurar junta com o que já existe; não apaga nada.
- **QR codes** (só códigos 2FA): **Export / transfer** → **Show QR codes**. Funcionam no Google Authenticator, neste app e na maioria dos autenticadores. Quem vir esses QR codes pode copiar suas contas.
- **Um código só**: no Android, segure o dedo no código → **Show QR code**; no Windows, selecione o código → **Show QR code…**. É um QR `otpauth://` comum, que qualquer autenticador lê.
- Em **Export** dá para escolher quais códigos e senhas entram (**Choose…** no Android, caixas de seleção no Windows).

### Senhas

- **Android**: aba **Passwords** embaixo. Toque numa senha para ver/editar; o botão de copiar ao lado copia a senha; segure o dedo para copiar usuário ou código 2FA.
- **Windows**: **View** → **Passwords** (Ctrl+2). **File** → **Import passwords from browser (CSV)…** importa o CSV exportado pelo Chrome/Thorium/Edge, Firefox ou Bitwarden.
- Cada senha pode ser ligada a um código 2FA (campo "2FA code"): aí o app e a extensão mostram/preenchem o código junto.
- **Generate a password** (Android) / **Tools** → **Password generator…** (Ctrl+G, Windows) cria senhas aleatórias.

### Extensão do navegador (Windows)

Funciona no Thorium, Chrome, Edge, Brave, Vivaldi e Opera. A extensão vem dentro
do `Authenticator.exe`; não precisa baixar nada.

1. No app: **Tools** → **Browser integration…** e ligue **Allow the browser extension to connect**.
2. No navegador, abra `thorium://extensions` (ou `chrome://extensions`) e ligue o **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação** e escolha a pasta mostrada no app (botões **Copy** / **Open folder**).
4. A extensão abre as configurações dela: clique em **Connect** e depois em **Allow** no app, se os dois mostrarem o mesmo código.

Uso:
- Numa página de login, clique no ícone do Authenticator na barra do navegador e escolha o login.
- Ou aperte **Ctrl+Shift+U**: preenche usuário e senha, ou o código 2FA na página seguinte.
- Se o app estiver bloqueado (ou fechado na área de notificação), a janela aparece pedindo o PIN e o preenchimento continua depois.
- Para salvar um login novo: digite na página, clique no ícone → **Save login from this page**.
- Em **Settings** dá para fazer o app perguntar antes de entregar cada senha ao navegador.

### Windows: área de notificação e iniciar com o Windows

- Fechar a janela (X) deixa o app rodando na área de notificação, perto do relógio (dá para desligar em **Settings**). Clique no ícone para abrir; clique com o botão direito para bloquear ou sair.
- **Settings** → **Start with Windows**: o app já começa bloqueado e escondido na área de notificação, pronto para a extensão.
- Abrir o `Authenticator.exe` de novo só mostra a janela que já está rodando.

### Windows: atalhos

| Tecla | Ação |
|---|---|
| Ctrl+1 / Ctrl+2 | códigos 2FA / senhas |
| Ctrl+N / Ctrl+Shift+N | adicionar código / senha |
| Enter ou duplo clique | copiar código ou senha |
| Ctrl+B / Ctrl+T | copiar usuário / código 2FA da senha |
| Ctrl+U | abrir o site |
| Ctrl+E / Del | editar / excluir |
| Ctrl+F | buscar |
| Ctrl+V | colar print de QR code |
| Ctrl+G | gerador de senhas |
| Ctrl+L | bloquear |
| Ctrl+W / Ctrl+Q | esconder na área de notificação / sair |

Para pegar um QR que está na tela: **Win+Shift+S**, selecione o QR, volte ao app e aperte **Ctrl+V**. Ou use **Tools** → **Scan screen for a QR code**.

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
cd windows; cargo test                 # Rust: RFC 4226/6238, importação, backup, cofre, QR, extensão
cd android; .\gradlew.bat -p core test # Kotlin: mesma lógica e mesmos vetores
```

Os dois conjuntos de testes usam os mesmos vetores em `docs/test-vectors/`,
incluindo um backup gerado por cada app, para garantir que um sempre abre o
backup do outro.

## Estrutura

```
windows/            App do Windows (Rust)
  src/              núcleo (otp, migration, backup, crypto, vault, login, csv, merge)
  src/gui/          interface, área de notificação, integração com o navegador
  src/browser/      protocolo da extensão, pipe local e host de native messaging
  ui/app.slint      telas
browser-extension/  extensão para navegadores Chromium (Manifest V3)
android/
  core/             lógica em Kotlin puro (testada no PC, sem Android)
  app/              app Android (Compose, CameraX, Keystore, biometria)
docs/               formato do backup, protocolo da extensão e vetores de teste
scripts/            scripts de compilação para o Windows
.github/workflows/  CI: compila e testa os dois apps
```

## Créditos

Interface do Windows feita com [Slint](https://slint.dev). Ícones Material Design
(Apache 2.0). Leitura de QR no Android com ZXing (Apache 2.0) e no Windows com
rqrr. Argon2 no Android pelo Bouncy Castle; criptografia no Windows pelos crates
RustCrypto.
