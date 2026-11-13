//! Browser integration: the Authenticator extension asks this app for the
//! saved logins of the page it is on, through a small "native messaging"
//! host that the browser starts (see `docs/browser-protocol.md`).
//!
//! browser extension <-stdio-> host (this program, `host.rs`) <-pipe-> app
//!
//! Everything stays on the PC. The extension and the app share a random key,
//! agreed once when the user connects the extension (and confirms a code in
//! the app); every request and answer is encrypted and authenticated with it.

pub mod host;
pub mod install;
pub mod ipc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::login::{Login, Password, match_score};

/// Name of the native messaging host, as registered with the browsers.
pub const HOST_NAME: &str = "app.authenticator.browser";
/// Id of the extension, fixed by the public key in its manifest.
pub const EXTENSION_ID: &str = "camkpchgligkkfchbhidopnijiipaikm";
pub const PROTOCOL_VERSION: u32 = 1;
/// Requests older or newer than this (seconds) are refused.
pub const MAX_CLOCK_SKEW: i64 = 120;

pub fn extension_origin() -> String {
    format!("chrome-extension://{EXTENSION_ID}/")
}

/// Code shown both in the extension and in the app when connecting, so the
/// user can check they are talking to each other: "1234-5678".
pub fn pair_code(key: &[u8]) -> String {
    let hash = Sha256::digest(key);
    let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 100_000_000;
    format!("{:04}-{:04}", n / 10_000, n % 10_000)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

fn aad(client: &str, direction: Direction) -> Vec<u8> {
    let dir = match direction {
        Direction::Request => "req",
        Direction::Response => "res",
    };
    format!("authenticator-browser:v1:{dir}:{client}").into_bytes()
}

/// Encrypts a message; returns (nonce, data) in base64.
pub fn seal(key: &[u8; 32], client: &str, direction: Direction, plaintext: &[u8]) -> (String, String) {
    let nonce: [u8; 12] = crypto::random();
    let cipher = Aes256Gcm::new(key.into());
    let aad = aad(client, direction);
    let data = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: &aad })
        .expect("AES-GCM encryption cannot fail for in-memory buffers");
    (B64.encode(nonce), B64.encode(data))
}

pub fn open(key: &[u8; 32], client: &str, direction: Direction, nonce: &str, data: &str) -> Option<Zeroizing<Vec<u8>>> {
    let nonce: [u8; 12] = B64.decode(nonce).ok()?.try_into().ok()?;
    let data = B64.decode(data).ok()?;
    let cipher = Aes256Gcm::new(key.into());
    let aad = aad(client, direction);
    cipher.decrypt(&Nonce::from(nonce), Payload { msg: &data, aad: &aad }).ok().map(Zeroizing::new)
}

pub fn decode_key(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(B64.decode(text.trim()).ok()?);
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(Zeroizing::new(key))
}

/// Outer message, as sent by the extension (through the host).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Envelope {
    #[serde(rename = "type")]
    pub kind: String,
    pub client: String,
    /// Pairing: name of the browser and the new key.
    pub name: String,
    pub key: String,
    /// Encrypted request.
    pub nonce: String,
    pub data: String,
    /// Show the app and wait for the user to unlock it if needed.
    pub wait: bool,
}

/// Decrypted request.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Request {
    pub id: String,
    pub ts: i64,
    pub action: String,
    pub url: String,
    pub login: String,
    pub fields: Vec<String>,
    pub title: String,
    pub username: String,
    pub password: Password,
}

#[derive(Debug, Serialize)]
pub struct LoginSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub otp: bool,
}

/// Logins that may be offered on `page_url`, best matches first.
pub fn matching_logins<'a>(logins: &'a [Login], page_url: &str) -> Vec<&'a Login> {
    let mut found: Vec<(u8, &Login)> =
        logins.iter().filter_map(|l| match_score(&l.url, page_url).map(|score| (score, l))).collect();
    found.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.display_title().to_lowercase().cmp(&b.1.display_title().to_lowercase()))
            .then_with(|| a.1.username.to_lowercase().cmp(&b.1.username.to_lowercase()))
    });
    found.into_iter().map(|(_, l)| l).collect()
}

/// Keeps the ids of recent requests per client to refuse replays.
#[derive(Default)]
pub struct ReplayGuard {
    seen: std::collections::HashMap<String, Vec<(String, i64)>>,
}

impl ReplayGuard {
    /// True if the request is fresh (and remembers it).
    pub fn check(&mut self, client: &str, id: &str, ts: i64, now: i64) -> bool {
        if id.is_empty() || id.len() > 64 || (ts - now).abs() > MAX_CLOCK_SKEW {
            return false;
        }
        let seen = self.seen.entry(client.to_string()).or_default();
        seen.retain(|(_, t)| (now - t).abs() <= MAX_CLOCK_SKEW * 2);
        if seen.iter().any(|(seen_id, _)| seen_id == id) {
            return false;
        }
        seen.push((id.to_string(), ts));
        true
    }
}

/// A plain (not encrypted) error answer, for requests that cannot be read.
pub fn plain_error(error: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "type": "error", "error": error })).expect("serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_roundtrip_and_binding() {
        let key = [7u8; 32];
        let (nonce, data) = seal(&key, "client-a", Direction::Request, b"{\"action\":\"status\"}");
        assert_eq!(
            open(&key, "client-a", Direction::Request, &nonce, &data).as_deref().map(|v| v.as_slice()),
            Some(&b"{\"action\":\"status\"}"[..])
        );
        // Bound to the client and the direction.
        assert!(open(&key, "client-b", Direction::Request, &nonce, &data).is_none());
        assert!(open(&key, "client-a", Direction::Response, &nonce, &data).is_none());
        assert!(open(&[8u8; 32], "client-a", Direction::Request, &nonce, &data).is_none());
    }

    #[test]
    fn known_vector_matches_the_extension() {
        // Same values as the extension's self-test (browser-extension/crypto.js).
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = B64.encode([1u8; 12]);
        let cipher = Aes256Gcm::new((&key).into());
        let data = cipher
            .encrypt(&Nonce::from([1u8; 12]), Payload { msg: b"hello", aad: b"authenticator-browser:v1:req:abc" })
            .unwrap();
        let data = B64.encode(data);
        assert_eq!(open(&key, "abc", Direction::Request, &nonce, &data).unwrap().as_slice(), b"hello");
        assert_eq!(pair_code(&key), pair_code(&key));
        assert_eq!(pair_code(&key).len(), 9);
    }

    #[test]
    fn replay_guard() {
        let mut guard = ReplayGuard::default();
        assert!(guard.check("c", "r1", 1000, 1000));
        assert!(!guard.check("c", "r1", 1000, 1001), "same id twice");
        assert!(guard.check("d", "r1", 1000, 1001), "ids are per client");
        assert!(!guard.check("c", "r2", 1000 - MAX_CLOCK_SKEW - 1, 1000), "too old");
        assert!(!guard.check("c", "r3", 1000 + MAX_CLOCK_SKEW + 1, 1000), "from the future");
        assert!(!guard.check("c", "", 1000, 1000));
    }

    #[test]
    fn matching_orders_best_first() {
        let login = |title: &str, url: &str| Login {
            title: title.into(),
            url: url.into(),
            password: Password::new("x"),
            ..Default::default()
        };
        let logins = vec![
            login("Example main", "https://example.com"),
            login("Example accounts", "https://accounts.example.com"),
            login("Evil", "https://example.com.evil.net"),
            login("Other", "https://other.org"),
        ];
        let found: Vec<&str> =
            matching_logins(&logins, "https://accounts.example.com/signin").iter().map(|l| l.title.as_str()).collect();
        assert_eq!(found, ["Example accounts", "Example main"]);
        assert!(matching_logins(&logins, "http://example.com/").is_empty(), "no https logins on http pages");
    }
}
