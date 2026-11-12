//! Accounts, TOTP/HOTP code generation (RFC 4226 / RFC 6238) and
//! `otpauth://` URI parsing.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::base32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Algorithm {
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OtpKind {
    #[default]
    Totp,
    Hotp,
}

/// Raw secret bytes. Wiped from memory when dropped; serialized as base32.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_base32(&self) -> String {
        base32::encode(&self.0)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut encoded = self.to_base32();
        let result = s.serialize_str(&encoded);
        encoded.zeroize();
        result
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut text = String::deserialize(d)?;
        let decoded = base32::decode(&text).map_err(serde::de::Error::custom);
        text.zeroize();
        Ok(Secret(decoded?))
    }
}

fn default_digits() -> u32 {
    6
}
fn default_period() -> u32 {
    30
}

/// One OTP account. This is also the exact JSON shape used inside backups,
/// shared with the Android app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    #[serde(rename = "type", default)]
    pub kind: OtpKind,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub name: String,
    pub secret: Secret,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_period")]
    pub period: u32,
    #[serde(default)]
    pub counter: u64,
}

impl Account {
    /// Validates parameters coming from untrusted input (URIs, backups, QR codes).
    pub fn validate(&self) -> Result<(), String> {
        if self.secret.bytes().is_empty() {
            return Err("Secret is empty".into());
        }
        if !(6..=8).contains(&self.digits) {
            return Err(format!("Unsupported number of digits: {}", self.digits));
        }
        if self.kind == OtpKind::Totp && !(1..=600).contains(&self.period) {
            return Err(format!("Unsupported period: {}", self.period));
        }
        if self.issuer.chars().count() > 256 || self.name.chars().count() > 256 {
            return Err("Name or issuer is too long".into());
        }
        Ok(())
    }

    /// Same account (same secret and labels)? Used to skip duplicates on import.
    pub fn same_as(&self, other: &Account) -> bool {
        self.secret == other.secret
            && self.kind == other.kind
            && self.issuer == other.issuer
            && self.name == other.name
    }

    pub fn display_title(&self) -> String {
        match (self.issuer.is_empty(), self.name.is_empty()) {
            (false, _) => self.issuer.clone(),
            (true, false) => self.name.clone(),
            (true, true) => "(no name)".into(),
        }
    }

    /// Code for the given unix time (TOTP) or for the stored counter (HOTP).
    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = match self.kind {
            OtpKind::Totp => unix_time / self.period.max(1) as u64,
            OtpKind::Hotp => self.counter,
        };
        hotp(self.secret.bytes(), counter, self.digits, self.algorithm)
    }

    /// Seconds until the current TOTP code changes.
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        let period = self.period.max(1) as u64;
        period - (unix_time % period)
    }
}

fn mac_bytes<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 4226 HOTP value.
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algorithm: Algorithm) -> String {
    let msg = counter.to_be_bytes();
    let mut hash = match algorithm {
        Algorithm::Sha1 => mac_bytes::<Hmac<sha1::Sha1>>(secret, &msg),
        Algorithm::Sha256 => mac_bytes::<Hmac<sha2::Sha256>>(secret, &msg),
        Algorithm::Sha512 => mac_bytes::<Hmac<sha2::Sha512>>(secret, &msg),
    };
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    hash.zeroize();
    let modulus = 10u32.pow(digits);
    format!("{:0width$}", binary % modulus, width = digits as usize)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Percent-decodes a URI component. `plus_is_space` applies to query values.
pub fn percent_decode(input: &str, plus_is_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits a URI query into decoded key/value pairs (keys lower-cased).
pub fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k, true).to_ascii_lowercase(), percent_decode(v, true))
        })
        .collect()
}

/// Parses `otpauth://totp/Issuer:name?secret=...&issuer=...`.
pub fn parse_otpauth(uri: &str) -> Result<Account, String> {
    let uri = uri.trim();
    let rest = strip_prefix_ci(uri, "otpauth://").ok_or("Not an otpauth:// link")?;
    let (kind_str, rest) = rest.split_once('/').ok_or("Malformed otpauth link")?;
    let kind = match kind_str.to_ascii_lowercase().as_str() {
        "totp" => OtpKind::Totp,
        "hotp" => OtpKind::Hotp,
        other => return Err(format!("Unsupported OTP type '{other}'")),
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label, false);
    let (mut issuer, name) = match label.split_once(':') {
        Some((i, n)) => (i.trim().to_string(), n.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let mut secret = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6;
    let mut period = 30;
    let mut counter = None;
    for (key, value) in query_pairs(query) {
        match key.as_str() {
            "secret" => secret = Some(base32::decode(&value)?),
            "issuer" if !value.trim().is_empty() => issuer = value.trim().to_string(),
            "algorithm" => {
                algorithm = Algorithm::parse(&value)
                    .ok_or_else(|| format!("Unsupported algorithm '{value}'"))?
            }
            "digits" => digits = value.trim().parse().map_err(|_| "Invalid digits value")?,
            "period" => period = value.trim().parse().map_err(|_| "Invalid period value")?,
            "counter" => counter = Some(value.trim().parse().map_err(|_| "Invalid counter value")?),
            _ => {}
        }
    }
    let secret = secret.ok_or("The link has no secret")?;
    if kind == OtpKind::Hotp && counter.is_none() {
        return Err("HOTP link has no counter".into());
    }
    let account = Account {
        kind,
        issuer,
        name,
        secret: Secret::new(secret),
        algorithm,
        digits,
        period,
        counter: counter.unwrap_or(0),
    };
    account.validate()?;
    Ok(account)
}

pub fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED20: &[u8] = b"12345678901234567890";
    const SEED32: &[u8] = b"12345678901234567890123456789012";
    const SEED64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc4226_hotp() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
            "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(SEED20, counter as u64, 6, Algorithm::Sha1), *code);
        }
    }

    #[test]
    fn rfc6238_totp() {
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in cases {
            let mk = |secret: &[u8], algorithm| Account {
                kind: OtpKind::Totp,
                issuer: String::new(),
                name: String::new(),
                secret: Secret::new(secret.to_vec()),
                algorithm,
                digits: 8,
                period: 30,
                counter: 0,
            };
            assert_eq!(mk(SEED20, Algorithm::Sha1).code_at(time), sha1);
            assert_eq!(mk(SEED32, Algorithm::Sha256).code_at(time), sha256);
            assert_eq!(mk(SEED64, Algorithm::Sha512).code_at(time), sha512);
        }
    }

    #[test]
    fn parse_full_uri() {
        let a = parse_otpauth(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(a.issuer, "ACME Co");
        assert_eq!(a.name, "john.doe@email.com");
        assert_eq!(a.algorithm, Algorithm::Sha256);
        assert_eq!(a.digits, 8);
        assert_eq!(a.period, 60);
        assert_eq!(a.secret.to_base32(), "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ");
    }

    #[test]
    fn parse_minimal_and_errors() {
        let a = parse_otpauth("OTPAUTH://TOTP/alice?secret=jbswy3dpehpk3pxp").unwrap();
        assert_eq!(a.name, "alice");
        assert_eq!(a.issuer, "");
        assert_eq!(a.digits, 6);
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12").is_err());
        assert!(parse_otpauth("otpauth://totp/x").is_err());
        assert!(parse_otpauth("https://example.com").is_err());
        let h = parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=5").unwrap();
        assert_eq!(h.counter, 5);
    }

    #[test]
    fn percent_decoding_edges() {
        assert_eq!(percent_decode("a%20b", false), "a b");
        assert_eq!(percent_decode("100%", false), "100%");
        assert_eq!(percent_decode("%4", false), "%4");
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(percent_decode("a+b", false), "a+b");
    }
}
