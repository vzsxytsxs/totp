# Backup file format

Both apps (Windows and Android) read and write the same password-protected
backup file, so accounts can be moved in either direction. The same envelope
is also used, with a different `format` string, for the Windows app's local
storage.

## Envelope (JSON, UTF-8)

```json
{
  "format": "authenticator-backup",
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "<base64, 16 random bytes>"
  },
  "cipher": {
    "algorithm": "aes-256-gcm",
    "nonce": "<base64, 12 random bytes>"
  },
  "data": "<base64 of ciphertext || 16-byte GCM tag>"
}
```

* **Key**: Argon2id (version 0x13) of the password, 32-byte output, using the
  salt and parameters in `kdf`. The password is normalized to Unicode NFC and
  encoded as UTF-8 first, so it gives the same key on every keyboard/platform.
* **Encryption**: AES-256-GCM with the `nonce`, 128-bit tag, and associated
  data equal to the ASCII string `"<format>:v<version>"`
  (`authenticator-backup:v1`).
* Readers reject parameters outside `memory_kib` 8192–1048576,
  `iterations` 1–16, `parallelism` 1–16, salts shorter than 16 bytes and nonces
  that are not 12 bytes. A wrong password and a modified file both fail the
  GCM check.

## Plaintext

```json
{
  "version": 1,
  "entries": [
    {
      "type": "totp",
      "issuer": "GitHub",
      "name": "octocat",
      "secret": "JBSWY3DPEHPK3PXP",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "counter": 0
    }
  ]
}
```

| Field       | Values                                          |
|-------------|-------------------------------------------------|
| `type`      | `totp` or `hotp`                                |
| `secret`    | base32, upper case, no padding                  |
| `algorithm` | `SHA1`, `SHA256`, `SHA512`                      |
| `digits`    | 6, 7 or 8                                       |
| `period`    | seconds (TOTP)                                  |
| `counter`   | next counter value (HOTP)                       |

Missing optional fields default to `totp`, empty strings, `SHA1`, 6 digits,
30 seconds and counter 0. Entries that fail validation are skipped and
reported, not fatal.

## Test vectors

`docs/test-vectors/vectors.json` holds RFC 4226/6238 codes, `otpauth://`
parsing cases, a Google Authenticator export and two backup files: one
written by the Windows app and one written by the Android app. Both test
suites (`cargo test` in `windows/`, `./gradlew -p core test` in `android/`)
check all of them, so each app is proven to read the other's backups.

## Google Authenticator export

The QR export uses Google's `otpauth-migration://offline?data=…` format
(base64 protobuf `MigrationPayload`). It has no period field and only supports
6 or 8 digits, so accounts with other settings are left out of the QR export
and must be moved with a backup file. Large exports are split over several QR
codes (`batch_size`, `batch_index`, `batch_id`); each code can be imported on
its own.
