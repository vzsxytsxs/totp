# Browser integration protocol

The Authenticator browser extension (`browser-extension/`, Manifest V3, for
Chromium-based browsers) fills in logins saved in the Windows app. Everything
stays on the PC; nothing uses the network.

```
extension ──native messaging (stdio)──▶ host ──named pipe──▶ Authenticator app
```

## Pieces

| Piece | What it is |
| --- | --- |
| Extension | Fixed id `camkpchgligkkfchbhidopnijiipaikm` (set by the public `key` in `manifest.json`). Loaded with "Load unpacked" from the folder the app extracts. |
| Host | `%LOCALAPPDATA%\Authenticator\browser\authenticator-host.exe`: a copy of the app marked as a console program. Browsers start it with the caller's origin as the first argument; it refuses any other extension. It only relays messages, and starts the app (`--tray`) if it is not running. `app-path.txt` next to it says where the app is. |
| Host manifest | `app.authenticator.browser.json` in the same folder, registered (default value) under `HKCU\Software\<browser>\NativeMessagingHosts\app.authenticator.browser` for Google\Chrome, Chromium, Thorium, Microsoft\Edge, BraveSoftware\Brave-Browser and Vivaldi. `allowed_origins` lists only the extension above. |
| Pipe | `\\.\pipe\app.authenticator.browser-<user SID>`, created by the app with a DACL that allows only the current user and SYSTEM, `PIPE_REJECT_REMOTE_CLIENTS` and `FILE_FLAG_FIRST_PIPE_INSTANCE`. |

Turning the integration off in the app removes the registry keys, the host and
its manifest; the pipe then answers every message with `disabled`.

## Framing

Both legs use the native messaging framing: a 4-byte little-endian length,
then UTF-8 JSON. Messages are limited to 1 MiB. On a connection, every
message gets exactly one answer, in order.

## Messages from the extension

| `type` | Fields | Answer |
| --- | --- | --- |
| `ping` | – | Answered by the host itself: `{"type":"pong","version":"2.0.0","protocol":1}`. |
| `pair` | `client`, `name`, `key` | `{"type":"paired"}` once the user clicks **Allow** in the app, which shows the same code as the extension. |
| `request` | `client`, `nonce`, `data`, `wait` | `{"type":"response","nonce":…,"data":…}` (encrypted). |

Errors are plain: `{"type":"error","error":"<code>"}` with codes such as
`disabled`, `locked`, `unknown-client`, `bad-request`, `expired`, `denied`,
`busy`, `timeout`, `cancelled`, `app-not-found`, `app-not-running`.

`client` is a random id made by the extension (8–64 letters, digits, `-`,
`_`). While the app is locked, a `pair` request, or a `request` with
`wait: true`, brings the window up for the PIN and is answered after
unlocking (at most 150 s); other requests get `locked`.

## Pairing and encryption

- The extension makes a random 32-byte key and sends it (base64) in `pair`.
  Both sides show `SHA-256(key)`: the first 4 bytes as a big-endian number,
  modulo 100,000,000, as `1234-5678`. The app stores the key in its encrypted
  vault with the client id and name.
- A `request` carries AES-256-GCM with a random 12-byte nonce (base64) and
  additional data `authenticator-browser:v1:req:<client>`. Answers use
  `authenticator-browser:v1:res:<client>`.
- The decrypted request is JSON with `id` (random, at most 64 characters),
  `ts` (Unix seconds) and `action`. The app refuses a request more than 120 s
  away from its clock or with an `id` it has already seen. Each answer repeats
  the request `id`; the extension checks it.

## Actions

| `action` | Fields | Answer (decrypted) |
| --- | --- | --- |
| `status`, `unlock` | – | `{"ok":true,"name":"<client name>"}` |
| `logins` | `url` | `{"ok":true,"logins":[{"id","title","username","otp"}]}`: the logins whose website matches `url`, best first. `otp` says whether a 2FA account is linked. No passwords. |
| `fill` | `url`, `login`, `fields` (`username`, `password`, `otp`) | `{"ok":true,"username":…,"password":…,"otp":…,"otp_remaining":…}`, only the fields asked for. The app checks again that the login matches `url`. With "Ask me before giving a password to the browser" on, the app asks first. A counter-based (HOTP) code is used up. |
| `save` | `url`, `title`, `username`, `password` | `{"ok":true,"updated":bool}`. Updates the login with the same website host and user name, or adds one with the page's origin as its website. |

Failures inside an answer are `{"ok":false,"error":"<code>"}` (`not-found`,
`not-allowed`, `bad-url`, `empty-password`, `invalid`, `save-failed`).

## Website matching

A login is offered on a page only if (`login.rs`, `match_score`):

- the page is `http` or `https`;
- a login saved for `https://` (or without a scheme) is never given to an
  `http://` page, except for IP addresses and `localhost`;
- the host is the same (ignoring `www.`), or the page is on a subdomain of the
  saved host (`accounts.example.com` for `example.com`), never a look-alike
  (`example.com.evil.net`);
- a port in the saved address matches.

The extension fills only the top frame of the tab, and checks just before
filling that the page is still on the origin it asked about.

## Threat model

Protected against: websites (they never talk to the app; matching is done by
the app with the URL the browser reports), other extensions (the host only
accepts this extension's id), other Windows users and the network (pipe
DACL, local only), and a program that only talks to the pipe (it needs the
key from pairing, which the user confirms in the app). Not protected against
malware running as the same Windows user: it could read the extension's
storage or the browser's memory.
