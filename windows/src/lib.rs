//! Core logic of the Authenticator desktop app (no UI code here).

pub mod backup;
pub mod base32;
pub mod crypto;
pub mod csv;
pub mod login;
pub mod merge;
pub mod migration;
pub mod otp;
pub mod platform;
pub mod prefs;
pub mod qr;
pub mod tray;
pub mod vault;

use otp::Account;

/// Result of interpreting a scanned/pasted QR code or text.
#[derive(Default, Debug)]
pub struct ImportResult {
    pub accounts: Vec<Account>,
    pub messages: Vec<String>,
    /// For Google Authenticator exports split over several QR codes.
    pub batch: Option<(u32, u32)>,
}

/// Interprets an `otpauth://` or `otpauth-migration://` text.
pub fn parse_import_text(text: &str) -> Result<ImportResult, String> {
    let text = text.trim();
    if migration::is_migration_uri(text) {
        let batch = migration::decode_uri(text)?;
        Ok(ImportResult {
            batch: (batch.batch_size > 1).then_some((batch.batch_index + 1, batch.batch_size)),
            accounts: batch.accounts,
            messages: batch.skipped,
        })
    } else if otp::strip_prefix_ci(text, "otpauth://").is_some() {
        Ok(ImportResult { accounts: vec![otp::parse_otpauth(text)?], ..Default::default() })
    } else {
        Err("This QR code is not an authenticator code".into())
    }
}
