//! Google Authenticator "Transfer accounts" format:
//! `otpauth-migration://offline?data=<base64 protobuf MigrationPayload>`.
//!
//! ```proto
//! message MigrationPayload {
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5;
//! }
//! message OtpParameters {
//!   bytes secret = 1; string name = 2; string issuer = 3;
//!   Algorithm algorithm = 4;  // 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
//!   DigitCount digits = 5;    // 0 unspecified, 1 six, 2 eight
//!   OtpType type = 6;         // 0 unspecified, 1 HOTP, 2 TOTP
//!   int64 counter = 7;
//! }
//! ```

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

use crate::otp::{Account, Algorithm, OtpKind, Secret, percent_decode, strip_prefix_ci};

/// Accounts decoded from one migration QR code.
#[derive(Debug, Default)]
pub struct MigrationBatch {
    pub accounts: Vec<Account>,
    /// Entries that could not be imported (e.g. MD5), with the reason.
    pub skipped: Vec<String>,
    pub batch_index: u32,
    pub batch_size: u32,
    pub batch_id: i64,
}

pub fn is_migration_uri(text: &str) -> bool {
    strip_prefix_ci(text.trim(), "otpauth-migration://").is_some()
}

pub fn decode_uri(uri: &str) -> Result<MigrationBatch, String> {
    let rest = strip_prefix_ci(uri.trim(), "otpauth-migration://").ok_or("Not a Google Authenticator export code")?;
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    // Only `+` must survive here: it is part of the base64 alphabet.
    let data = query
        .split('&')
        .find_map(|p| p.split_once('=').filter(|(k, _)| k.eq_ignore_ascii_case("data")).map(|(_, v)| v))
        .map(|v| percent_decode(v, false))
        .ok_or("The export code has no data")?;
    let data = data.trim().replace(' ', "+");
    let bytes = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&data).ok())
        .ok_or("The export code data is not valid base64")?;
    decode_payload(&bytes)
}

// ---------------------------------------------------------------- protobuf

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn varint(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.buf.get(self.pos).ok_or("Truncated data")?;
            self.pos += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err("Invalid varint".into())
    }
    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        let end = self.pos.checked_add(len).filter(|&e| e <= self.buf.len()).ok_or("Truncated data")?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn skip(&mut self, wire_type: u64) -> Result<(), String> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => self.pos += 8,
            2 => {
                self.bytes()?;
            }
            5 => self.pos += 4,
            _ => return Err("Unsupported protobuf field".into()),
        }
        if self.pos > self.buf.len() {
            return Err("Truncated data".into());
        }
        Ok(())
    }
}

fn decode_payload(buf: &[u8]) -> Result<MigrationBatch, String> {
    let mut batch = MigrationBatch { batch_size: 1, ..Default::default() };
    let mut r = Reader::new(buf);
    while !r.done() {
        let key = r.varint()?;
        match (key >> 3, key & 7) {
            (1, 2) => {
                let entry = r.bytes()?;
                match decode_otp_parameters(entry)? {
                    Ok(account) => batch.accounts.push(account),
                    Err(reason) => batch.skipped.push(reason),
                }
            }
            (3, 0) => batch.batch_size = r.varint()? as u32,
            (4, 0) => batch.batch_index = r.varint()? as u32,
            (5, 0) => batch.batch_id = r.varint()? as i32 as i64,
            (_, wt) => r.skip(wt)?,
        }
    }
    batch.batch_size = batch.batch_size.max(1);
    Ok(batch)
}

/// Outer error = corrupt data; inner error = valid entry we cannot use.
fn decode_otp_parameters(buf: &[u8]) -> Result<Result<Account, String>, String> {
    let mut r = Reader::new(buf);
    let (mut secret, mut name, mut issuer) = (Vec::new(), String::new(), String::new());
    let (mut algorithm, mut digits, mut kind, mut counter) = (0u64, 0u64, 0u64, 0u64);
    while !r.done() {
        let key = r.varint()?;
        match (key >> 3, key & 7) {
            (1, 2) => secret = r.bytes()?.to_vec(),
            (2, 2) => name = String::from_utf8_lossy(r.bytes()?).into_owned(),
            (3, 2) => issuer = String::from_utf8_lossy(r.bytes()?).into_owned(),
            (4, 0) => algorithm = r.varint()?,
            (5, 0) => digits = r.varint()?,
            (6, 0) => kind = r.varint()?,
            (7, 0) => counter = r.varint()?,
            (_, wt) => r.skip(wt)?,
        }
    }
    // Google puts "Issuer:name" in the name field when an issuer exists.
    let mut name = name.trim().to_string();
    if !issuer.is_empty() {
        if let Some(stripped) = name.strip_prefix(&format!("{issuer}:")) {
            name = stripped.trim().to_string();
        }
    }
    let label = if issuer.is_empty() { name.clone() } else { format!("{issuer} ({name})") };
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Ok(Err(format!("{label}: unsupported algorithm (MD5)"))),
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return Ok(Err(format!("{label}: unsupported digit count"))),
    };
    let kind = match kind {
        1 => OtpKind::Hotp,
        _ => OtpKind::Totp,
    };
    let account = Account {
        id: String::new(),
        kind,
        issuer: issuer.trim().to_string(),
        name,
        secret: Secret::new(secret),
        algorithm,
        digits,
        period: 30,
        counter,
    };
    Ok(account.validate().map(|_| account).map_err(|e| format!("{label}: {e}")))
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn put_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, field << 3);
    put_varint(out, v);
}

/// Accounts Google Authenticator's format cannot carry (it has no period
/// field and only supports 6 or 8 digits).
pub fn exportable(account: &Account) -> bool {
    (account.kind == OtpKind::Hotp || account.period == 30) && (account.digits == 6 || account.digits == 8)
}

fn encode_otp_parameters(a: &Account) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, 1, a.secret.bytes());
    put_bytes(&mut out, 2, a.name.as_bytes());
    if !a.issuer.is_empty() {
        put_bytes(&mut out, 3, a.issuer.as_bytes());
    }
    put_uint(
        &mut out,
        4,
        match a.algorithm {
            Algorithm::Sha1 => 1,
            Algorithm::Sha256 => 2,
            Algorithm::Sha512 => 3,
        },
    );
    put_uint(&mut out, 5, if a.digits == 8 { 2 } else { 1 });
    put_uint(&mut out, 6, if a.kind == OtpKind::Hotp { 1 } else { 2 });
    if a.kind == OtpKind::Hotp {
        put_uint(&mut out, 7, a.counter);
    }
    out
}

/// Payload bytes per QR code. Keeps codes dense enough to scan from a screen.
const MAX_BATCH_BYTES: usize = 600;

/// Builds the `otpauth-migration://` URIs (one per QR code) for `accounts`.
/// Accounts that are not [`exportable`] must be filtered out by the caller.
pub fn encode_uris(accounts: &[&Account], batch_id: i32) -> Vec<String> {
    let entries: Vec<Vec<u8>> = accounts.iter().map(|a| encode_otp_parameters(a)).collect();
    let mut groups: Vec<Vec<&Vec<u8>>> = Vec::new();
    let mut size = 0;
    for entry in &entries {
        let cost = entry.len() + 3;
        if groups.is_empty() || (size + cost > MAX_BATCH_BYTES && !groups.last().unwrap().is_empty()) {
            groups.push(Vec::new());
            size = 0;
        }
        groups.last_mut().unwrap().push(entry);
        size += cost;
    }
    let batch_size = groups.len() as u64;
    groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let mut payload = Vec::new();
            for entry in group {
                put_bytes(&mut payload, 1, entry);
            }
            put_uint(&mut payload, 2, 1);
            put_uint(&mut payload, 3, batch_size);
            put_uint(&mut payload, 4, index as u64);
            put_uint(&mut payload, 5, batch_id as u32 as u64);
            let b64 = STANDARD.encode(&payload);
            let escaped = b64.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
            format!("otpauth-migration://offline?data={escaped}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base32;

    /// Widely published sample export (account "Example:alice@google.com").
    const SAMPLE: &str = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgACjr4JKcBA%3D%3D";

    #[test]
    fn decode_google_sample() {
        let batch = decode_uri(SAMPLE).unwrap();
        assert_eq!(batch.accounts.len(), 1);
        let a = &batch.accounts[0];
        assert_eq!(a.issuer, "Example");
        assert_eq!(a.name, "alice@google.com");
        assert_eq!(a.secret.bytes(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(base32::encode(a.secret.bytes()), "JBSWY3DPEHPK3PXP");
        assert_eq!(a.kind, OtpKind::Totp);
        assert_eq!(a.digits, 6);
        assert_eq!(batch.batch_size, 1);
    }

    fn account(i: usize, kind: OtpKind) -> Account {
        Account {
            id: String::new(),
            kind,
            issuer: format!("Issuer {i}"),
            name: format!("user{i}@example.com"),
            secret: Secret::new((0..20).map(|b| (b * 7 + i) as u8).collect()),
            algorithm: if i % 3 == 0 { Algorithm::Sha256 } else { Algorithm::Sha1 },
            digits: if i % 2 == 0 { 8 } else { 6 },
            period: 30,
            counter: if kind == OtpKind::Hotp { i as u64 } else { 0 },
        }
    }

    #[test]
    fn roundtrip_many_batches() {
        let accounts: Vec<Account> =
            (0..40).map(|i| account(i, if i % 5 == 0 { OtpKind::Hotp } else { OtpKind::Totp })).collect();
        let refs: Vec<&Account> = accounts.iter().collect();
        let uris = encode_uris(&refs, 12345);
        assert!(uris.len() > 1);
        let mut decoded = Vec::new();
        for (i, uri) in uris.iter().enumerate() {
            assert!(uri.len() < 1000, "uri too long: {}", uri.len());
            let batch = decode_uri(uri).unwrap();
            assert_eq!(batch.batch_index as usize, i);
            assert_eq!(batch.batch_size as usize, uris.len());
            assert_eq!(batch.batch_id, 12345);
            decoded.extend(batch.accounts);
        }
        assert_eq!(decoded, accounts);
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_uri("otpauth-migration://offline?data=%%%").is_err());
        assert!(decode_uri("otpauth-migration://offline?data=CgQKAg").is_err());
        assert!(decode_uri("otpauth://totp/x?secret=AAAA").is_err());
    }
}
