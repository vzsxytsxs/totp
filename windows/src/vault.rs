//! Local encrypted storage.
//!
//! Layers (outermost first):
//! 1. Windows DPAPI: the file can only be decrypted by the same Windows user.
//! 2. Argon2id(PIN) + AES-256-GCM: the PIN is required as well.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Envelope, EnvelopeError, KdfParams, SALT_LEN};
use crate::login::{GeneratorOptions, Login};
use crate::merge;
use crate::otp::Account;
use crate::platform;

pub const FORMAT: &str = "authenticator-vault";
pub const MIN_PIN_LEN: usize = 4;

#[cfg(windows)]
const MAGIC: &[u8; 8] = b"AUTHVLT1"; // DPAPI-wrapped envelope
#[cfg(not(windows))]
const MAGIC: &[u8; 8] = b"AUTHVLT0"; // plain envelope (development builds)

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 0 = never.
    pub auto_lock_minutes: u32,
    /// 0 = never clear.
    pub clipboard_clear_seconds: u32,
    pub hide_from_capture: bool,
    /// Lock when Windows locks (Win+L), the session switches or the PC sleeps.
    pub lock_on_session_lock: bool,
    /// Ask in the app before giving a password to the browser extension.
    pub confirm_browser_access: bool,
    pub generator: GeneratorOptions,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 30,
            hide_from_capture: true,
            lock_on_session_lock: true,
            confirm_browser_access: false,
            generator: GeneratorOptions::default(),
        }
    }
}

/// A browser extension that was allowed to connect (see `browser`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserClient {
    pub id: String,
    pub name: String,
    /// Base64 of the 32-byte key shared with the extension.
    pub key: String,
    pub created: i64,
    #[serde(default)]
    pub last_used: i64,
}

#[derive(Serialize)]
struct PayloadOut<'a> {
    version: u32,
    settings: &'a Settings,
    entries: &'a [Account],
    logins: &'a [Login],
    browsers: &'a [BrowserClient],
}

#[derive(Deserialize)]
struct PayloadIn {
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    settings: Settings,
    entries: Vec<Account>,
    #[serde(default)]
    logins: Vec<Login>,
    #[serde(default)]
    browsers: Vec<BrowserClient>,
}

#[derive(Debug)]
pub enum VaultError {
    WrongPin,
    Io(String),
    Corrupt(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::WrongPin => write!(f, "Wrong PIN"),
            VaultError::Io(e) => write!(f, "Could not access the data file: {e}"),
            VaultError::Corrupt(e) => write!(f, "The data file is damaged: {e}"),
        }
    }
}

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    pub settings: Settings,
    pub entries: Vec<Account>,
    pub logins: Vec<Login>,
    pub browsers: Vec<BrowserClient>,
}

pub fn default_path() -> PathBuf {
    platform::data_dir().join("vault.dat")
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

impl Vault {
    pub fn create(path: &Path, pin: &str) -> Result<Vault, VaultError> {
        let salt: [u8; SALT_LEN] = crypto::random();
        let params = KdfParams::DEFAULT;
        let key = crypto::derive_key(pin, &salt, &params).map_err(VaultError::Corrupt)?;
        let vault = Vault {
            path: path.to_path_buf(),
            key,
            salt,
            params,
            settings: Settings::default(),
            entries: Vec::new(),
            logins: Vec::new(),
            browsers: Vec::new(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, pin: &str) -> Result<Vault, VaultError> {
        let raw = fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let body =
            raw.strip_prefix(MAGIC.as_slice()).ok_or_else(|| VaultError::Corrupt("unknown file header".into()))?;
        let envelope_json = platform::unprotect(body).map_err(VaultError::Corrupt)?;
        let envelope = Envelope::parse(FORMAT, &envelope_json).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let key = crypto::derive_key(pin, &envelope.salt, &envelope.params).map_err(VaultError::Corrupt)?;
        let plaintext = envelope.open(&key).map_err(|e| match e {
            EnvelopeError::WrongPassword => VaultError::WrongPin,
            other => VaultError::Corrupt(other.to_string()),
        })?;
        let payload: PayloadIn = serde_json::from_slice(&plaintext).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let salt: [u8; SALT_LEN] = envelope.salt.as_slice().try_into().unwrap_or_else(|_| crypto::random()); // non-standard salt length: re-key on next save
        let mut vault = Vault {
            path: path.to_path_buf(),
            key,
            salt,
            params: envelope.params,
            settings: payload.settings,
            entries: payload.entries,
            logins: payload.logins,
            browsers: payload.browsers,
        };
        if envelope.salt.len() != SALT_LEN {
            vault.rekey(pin)?;
        } else if merge::ensure_ids(&mut vault.entries, &mut vault.logins) {
            vault.save()?;
        }
        Ok(vault)
    }

    fn rekey(&mut self, pin: &str) -> Result<(), VaultError> {
        self.salt = crypto::random();
        self.params = KdfParams::DEFAULT;
        self.key = crypto::derive_key(pin, &self.salt, &self.params).map_err(VaultError::Corrupt)?;
        self.save()
    }

    pub fn change_pin(&mut self, new_pin: &str) -> Result<(), VaultError> {
        self.rekey(new_pin)
    }

    /// Checks a PIN against the unlocked vault (constant-time comparison).
    pub fn verify_pin(&self, pin: &str) -> bool {
        self.pin_check().verify(pin)
    }

    /// What is needed to check the PIN on another thread (it takes a moment).
    pub fn pin_check(&self) -> PinCheck {
        PinCheck { key: self.key.clone(), salt: self.salt, params: self.params }
    }

    /// Writes atomically (temp file + rename) and keeps the previous file as `.bak`.
    pub fn save(&self) -> Result<(), VaultError> {
        let io = |e: std::io::Error| VaultError::Io(e.to_string());
        let mut plaintext = Zeroizing::new(Vec::with_capacity(256 * (self.entries.len() + self.logins.len()) + 256));
        let payload = PayloadOut {
            version: 1,
            settings: &self.settings,
            entries: &self.entries,
            logins: &self.logins,
            browsers: &self.browsers,
        };
        serde_json::to_writer(&mut *plaintext, &payload).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let envelope = crypto::seal(FORMAT, &self.key, &self.salt, &self.params, &plaintext);
        let protected = platform::protect(envelope.as_bytes()).map_err(VaultError::Io)?;

        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = self.path.with_extension("dat.tmp");
        {
            let mut file = fs::File::create(&tmp).map_err(io)?;
            file.write_all(MAGIC).map_err(io)?;
            file.write_all(&protected).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        if self.path.exists() {
            let _ = fs::copy(&self.path, self.path.with_extension("dat.bak"));
        }
        fs::rename(&tmp, &self.path).map_err(io)
    }
}

pub struct PinCheck {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

impl PinCheck {
    pub fn verify(&self, pin: &str) -> bool {
        match crypto::derive_key(pin, &self.salt, &self.params) {
            Ok(candidate) => candidate.iter().zip(self.key.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0,
            Err(_) => false,
        }
    }
}

/// Deletes all local data (used by "Forgot PIN" -> reset).
pub fn destroy(path: &Path) -> std::io::Result<()> {
    for p in [path.to_path_buf(), path.with_extension("dat.bak"), path.with_extension("dat.tmp")] {
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::parse_otpauth;

    #[test]
    fn create_unlock_change_pin() {
        let dir = std::env::temp_dir().join(format!("auth-test-{}", std::process::id()));
        let path = dir.join("vault.dat");
        let _ = destroy(&path);
        let mut v = Vault::create(&path, "1234").unwrap();
        v.entries.push(parse_otpauth("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP").unwrap());
        v.logins.push(Login {
            title: "Site".into(),
            password: crate::login::Password::new("pa55word"),
            ..Default::default()
        });
        v.settings.auto_lock_minutes = 15;
        v.save().unwrap();
        assert!(matches!(Vault::unlock(&path, "0000"), Err(VaultError::WrongPin)));
        let mut v2 = Vault::unlock(&path, "1234").unwrap();
        assert_eq!(v2.entries.len(), 1);
        assert_eq!(v2.logins[0].password.as_str(), "pa55word");
        assert!(!v2.entries[0].id.is_empty() && !v2.logins[0].id.is_empty(), "ids assigned on unlock");
        assert_eq!(v2.settings.auto_lock_minutes, 15);
        v2.change_pin("987654").unwrap();
        assert!(matches!(Vault::unlock(&path, "1234"), Err(VaultError::WrongPin)));
        assert_eq!(Vault::unlock(&path, "987654").unwrap().entries.len(), 1);
        let on_disk = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&on_disk).contains("JBSWY3DPEHPK3PXP"));
        assert!(!String::from_utf8_lossy(&on_disk).contains("pa55word"));
        destroy(&path).unwrap();
        let _ = fs::remove_dir(dir);
    }
}
