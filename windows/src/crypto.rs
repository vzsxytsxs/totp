//! Password-based encryption shared by the local vault and portable backups:
//! Argon2id (password -> 256-bit key) + AES-256-GCM.
//!
//! The envelope layout is documented in `docs/backup-format.md` and is
//! implemented identically by the Android app.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes: roughly 0.2-0.5 s on a desktop CPU.
    pub const DEFAULT: KdfParams = KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 };

    /// Rejects parameters from a file that would be insecure or would make
    /// us allocate absurd amounts of memory.
    fn check(&self) -> Result<(), EnvelopeError> {
        let ok = (8 * 1024..=1024 * 1024).contains(&self.memory_kib)
            && (1..=16).contains(&self.iterations)
            && (1..=16).contains(&self.parallelism);
        if ok { Ok(()) } else { Err(EnvelopeError::Unsupported("key derivation parameters".into())) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Not one of our files at all.
    WrongFormat,
    /// Ours, but a version/algorithm this build does not know.
    Unsupported(String),
    /// Authentication failed: wrong password (or tampered file).
    WrongPassword,
    Corrupt(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::WrongFormat => write!(f, "This is not an Authenticator file"),
            EnvelopeError::Unsupported(what) => write!(f, "Unsupported file ({what}). Update the app."),
            EnvelopeError::WrongPassword => write!(f, "Wrong password"),
            EnvelopeError::Corrupt(why) => write!(f, "The file is damaged: {why}"),
        }
    }
}

/// Passwords are NFC-normalized so the same password typed on different
/// keyboards/platforms (e.g. "ç" composed vs decomposed) gives the same key.
pub fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; 32]>, String> {
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let argon_params = argon2::Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(normalized.as_bytes(), salt, key.as_mut()).map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system random number generator failed");
    buf
}

/// Random id for accounts, logins and paired browsers (32 hex characters).
pub fn new_id() -> String {
    random::<16>().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize, Deserialize)]
struct KdfJson {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct CipherJson {
    algorithm: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct EnvelopeJson {
    format: String,
    version: u32,
    kdf: KdfJson,
    cipher: CipherJson,
    data: String,
}

pub const ENVELOPE_VERSION: u32 = 1;

fn aad(format: &str, version: u32) -> Vec<u8> {
    format!("{format}:v{version}").into_bytes()
}

/// Encrypts `plaintext` with an already-derived key and returns the JSON envelope.
pub fn seal(
    format: &str,
    key: &[u8; 32],
    salt: &[u8],
    params: &KdfParams,
    plaintext: &[u8],
) -> String {
    let nonce_bytes: [u8; NONCE_LEN] = random();
    let cipher = Aes256Gcm::new(key.into());
    let aad = aad(format, ENVELOPE_VERSION);
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce_bytes), Payload { msg: plaintext, aad: &aad })
        .expect("AES-GCM encryption cannot fail for in-memory buffers");
    let envelope = EnvelopeJson {
        format: format.to_string(),
        version: ENVELOPE_VERSION,
        kdf: KdfJson {
            algorithm: "argon2id".into(),
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
            salt: B64.encode(salt),
        },
        cipher: CipherJson { algorithm: "aes-256-gcm".into(), nonce: B64.encode(nonce_bytes) },
        data: B64.encode(ciphertext),
    };
    serde_json::to_string_pretty(&envelope).expect("serializable")
}

/// Parsed envelope header; decrypt with [`Envelope::open`].
pub struct Envelope {
    pub salt: Vec<u8>,
    pub params: KdfParams,
    format: String,
    nonce: [u8; NONCE_LEN],
    data: Vec<u8>,
}

impl Envelope {
    pub fn parse(expected_format: &str, json: &[u8]) -> Result<Envelope, EnvelopeError> {
        let env: EnvelopeJson = serde_json::from_slice(json).map_err(|_| EnvelopeError::WrongFormat)?;
        if env.format != expected_format {
            return Err(EnvelopeError::WrongFormat);
        }
        if env.version != ENVELOPE_VERSION {
            return Err(EnvelopeError::Unsupported(format!("version {}", env.version)));
        }
        if env.kdf.algorithm != "argon2id" {
            return Err(EnvelopeError::Unsupported(env.kdf.algorithm));
        }
        if env.cipher.algorithm != "aes-256-gcm" {
            return Err(EnvelopeError::Unsupported(env.cipher.algorithm));
        }
        let params = KdfParams {
            memory_kib: env.kdf.memory_kib,
            iterations: env.kdf.iterations,
            parallelism: env.kdf.parallelism,
        };
        params.check()?;
        let bad = |what: &str| EnvelopeError::Corrupt(format!("invalid {what}"));
        let salt = B64.decode(&env.kdf.salt).map_err(|_| bad("salt"))?;
        if !(SALT_LEN..=64).contains(&salt.len()) {
            return Err(bad("salt"));
        }
        let nonce: [u8; NONCE_LEN] = B64
            .decode(&env.cipher.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(|| bad("nonce"))?;
        let data = B64.decode(&env.data).map_err(|_| bad("data"))?;
        Ok(Envelope { salt, params, format: env.format, nonce, data })
    }

    pub fn open(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let cipher = Aes256Gcm::new(key.into());
        let aad = aad(&self.format, ENVELOPE_VERSION);
        cipher
            .decrypt(&Nonce::from(self.nonce), Payload { msg: &self.data, aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| EnvelopeError::WrongPassword)
    }
}
