//! Portable, password-protected backup file (Windows <-> Android).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Envelope, EnvelopeError, KdfParams, SALT_LEN};
use crate::login::Login;
use crate::otp::Account;

pub const FORMAT: &str = "authenticator-backup";
pub const MIN_PASSWORD_LEN: usize = 8;

// Version 1 payloads gained `logins` and account `id`s in app version 2.0.
// Both are optional, so older apps still read the accounts of newer backups.
#[derive(Serialize)]
struct PayloadOut<'a> {
    version: u32,
    entries: &'a [Account],
    #[serde(skip_serializing_if = "<[Login]>::is_empty")]
    logins: &'a [Login],
}

#[derive(Deserialize)]
struct PayloadIn {
    version: u32,
    entries: Vec<Account>,
    #[serde(default)]
    logins: Vec<Login>,
}

/// What a backup file holds.
#[derive(Debug, Default)]
pub struct Contents {
    pub accounts: Vec<Account>,
    pub logins: Vec<Login>,
    /// Entries that failed validation and were left out.
    pub invalid: usize,
}

/// Returns the backup file contents (JSON text).
pub fn create(accounts: &[Account], logins: &[Login], password: &str) -> Result<String, String> {
    create_with_params(accounts, logins, password, &KdfParams::DEFAULT)
}

pub fn create_with_params(
    accounts: &[Account],
    logins: &[Login],
    password: &str,
    params: &KdfParams,
) -> Result<String, String> {
    let salt: [u8; SALT_LEN] = crypto::random();
    let key = crypto::derive_key(password, &salt, params)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(256 * (accounts.len() + logins.len()) + 64));
    serde_json::to_writer(&mut *plaintext, &PayloadOut { version: 1, entries: accounts, logins })
        .map_err(|e| e.to_string())?;
    Ok(crypto::seal(FORMAT, &key, &salt, params, &plaintext))
}

/// Decrypts a backup. Entries that fail validation are dropped and counted.
pub fn open(contents: &[u8], password: &str) -> Result<Contents, EnvelopeError> {
    let envelope = Envelope::parse(FORMAT, contents)?;
    let key = crypto::derive_key(password, &envelope.salt, &envelope.params).map_err(EnvelopeError::Corrupt)?;
    let plaintext = envelope.open(&key)?;
    let payload: PayloadIn =
        serde_json::from_slice(&plaintext).map_err(|e| EnvelopeError::Corrupt(e.to_string()))?;
    if payload.version != 1 {
        return Err(EnvelopeError::Unsupported(format!("payload version {}", payload.version)));
    }
    let total = payload.entries.len() + payload.logins.len();
    let accounts: Vec<Account> = payload.entries.into_iter().filter(|a| a.validate().is_ok()).collect();
    let logins: Vec<Login> = payload.logins.into_iter().filter(|l| l.validate().is_ok()).collect();
    let invalid = total - accounts.len() - logins.len();
    Ok(Contents { accounts, logins, invalid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::parse_otpauth;

    const FAST: KdfParams = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

    #[test]
    fn roundtrip_and_wrong_password() {
        let accounts = vec![
            parse_otpauth("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP").unwrap(),
            parse_otpauth("otpauth://hotp/Bank:ação?secret=GEZDGNBVGY3TQOJQ&counter=7&digits=8").unwrap(),
        ];
        let logins = vec![Login {
            id: "l1".into(),
            title: "GitHub".into(),
            username: "me".into(),
            password: crate::login::Password::new("hunter2"),
            url: "https://github.com".into(),
            otp: "x".into(),
            created: 1,
            modified: 2,
            ..Default::default()
        }];
        let file = create_with_params(&accounts, &logins, "correct horse çá", &FAST).unwrap();
        assert!(!file.contains("JBSWY3DPEHPK3PXP") && !file.contains("hunter2"));
        let restored = open(file.as_bytes(), "correct horse çá").unwrap();
        assert_eq!(restored.accounts, accounts);
        assert_eq!(restored.logins, logins);
        assert_eq!(restored.invalid, 0);
        // Same password typed in decomposed form (c + combining cedilla).
        assert!(open(file.as_bytes(), "correct horse c\u{0327}a\u{0301}").is_ok());
        assert_eq!(open(file.as_bytes(), "wrong").unwrap_err(), EnvelopeError::WrongPassword);
        assert_eq!(open(b"{}", "x").unwrap_err(), EnvelopeError::WrongFormat);
        let tampered = file.replace("\"iterations\": 1", "\"iterations\": 2");
        assert_eq!(open(tampered.as_bytes(), "correct horse çá").unwrap_err(), EnvelopeError::WrongPassword);
    }

    #[test]
    fn rejects_hostile_kdf_params() {
        let accounts = vec![parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap()];
        let file = create_with_params(&accounts, &[], "password", &FAST).unwrap();
        let hostile = file.replace("\"memory_kib\": 8192", "\"memory_kib\": 4000000000");
        assert!(matches!(open(hostile.as_bytes(), "password"), Err(EnvelopeError::Unsupported(_))));
    }
}
