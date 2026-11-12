//! Portable, password-protected backup file (Windows <-> Android).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Envelope, EnvelopeError, KdfParams, SALT_LEN};
use crate::otp::Account;

pub const FORMAT: &str = "authenticator-backup";
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Serialize)]
struct PayloadOut<'a> {
    version: u32,
    entries: &'a [Account],
}

#[derive(Deserialize)]
struct PayloadIn {
    version: u32,
    entries: Vec<Account>,
}

/// Returns the backup file contents (JSON text).
pub fn create(accounts: &[Account], password: &str) -> Result<String, String> {
    create_with_params(accounts, password, &KdfParams::DEFAULT)
}

pub fn create_with_params(accounts: &[Account], password: &str, params: &KdfParams) -> Result<String, String> {
    let salt: [u8; SALT_LEN] = crypto::random();
    let key = crypto::derive_key(password, &salt, params)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(256 * accounts.len() + 64));
    serde_json::to_writer(&mut *plaintext, &PayloadOut { version: 1, entries: accounts })
        .map_err(|e| e.to_string())?;
    Ok(crypto::seal(FORMAT, &key, &salt, params, &plaintext))
}

/// Decrypts a backup. Entries that fail validation are dropped and counted.
pub fn open(contents: &[u8], password: &str) -> Result<(Vec<Account>, usize), EnvelopeError> {
    let envelope = Envelope::parse(FORMAT, contents)?;
    let key = crypto::derive_key(password, &envelope.salt, &envelope.params).map_err(EnvelopeError::Corrupt)?;
    let plaintext = envelope.open(&key)?;
    let payload: PayloadIn =
        serde_json::from_slice(&plaintext).map_err(|e| EnvelopeError::Corrupt(e.to_string()))?;
    if payload.version != 1 {
        return Err(EnvelopeError::Unsupported(format!("payload version {}", payload.version)));
    }
    let total = payload.entries.len();
    let valid: Vec<Account> = payload.entries.into_iter().filter(|a| a.validate().is_ok()).collect();
    let invalid = total - valid.len();
    Ok((valid, invalid))
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
        let file = create_with_params(&accounts, "correct horse çá", &FAST).unwrap();
        assert!(!file.contains("JBSWY3DPEHPK3PXP"));
        let (restored, invalid) = open(file.as_bytes(), "correct horse çá").unwrap();
        assert_eq!(restored, accounts);
        assert_eq!(invalid, 0);
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
        let file = create_with_params(&accounts, "password", &FAST).unwrap();
        let hostile = file.replace("\"memory_kib\": 8192", "\"memory_kib\": 4000000000");
        assert!(matches!(open(hostile.as_bytes(), "password"), Err(EnvelopeError::Unsupported(_))));
    }
}
