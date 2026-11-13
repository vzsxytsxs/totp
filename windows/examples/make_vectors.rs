//! Regenerates `docs/test-vectors/backup-v2-from-windows.json` (accounts
//! with ids and logins), which the Android test suite must decrypt.
//! `backup-from-windows.json` was written by version 1.0 and is kept as is,
//! to prove that old backups still open.
//!
//! Run: cargo run --example make_vectors

use authenticator::backup;
use authenticator::crypto::KdfParams;
use authenticator::login::{Login, Password};
use authenticator::otp::parse_otpauth;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/test-vectors/");

fn main() {
    // Small KDF parameters keep the tests fast; real backups use the defaults.
    let params = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };

    let mut accounts = vec![
        parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap(),
        parse_otpauth("otpauth://hotp/Legacy?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3").unwrap(),
    ];
    accounts[0].id = "0a1b2c3d4e5f60718293a4b5c6d7e8f9".into();
    accounts[1].id = "ffeeddccbbaa99887766554433221100".into();
    let logins = vec![
        Login {
            id: "11111111111111111111111111111111".into(),
            title: "GitHub".into(),
            username: "octocat".into(),
            password: Password::new("correct-horse-ção-🔑"),
            url: "https://github.com/login".into(),
            notes: "line 1\nline 2".into(),
            otp: accounts[0].id.clone(),
            created: 1_700_000_000,
            modified: 1_700_000_500,
        },
        Login {
            id: "22222222222222222222222222222222".into(),
            title: String::new(),
            username: "joão@example.com".into(),
            password: Password::new("p@ss \"quoted\" \\ end"),
            url: "example.com".into(),
            notes: String::new(),
            otp: String::new(),
            created: 1_700_000_000,
            modified: 1_700_000_000,
        },
    ];
    write(
        "backup-v2-from-windows.json",
        backup::create_with_params(&accounts, &logins, "senha forte do windows 2.0 ✓", &params).unwrap(),
    );
}

fn write(name: &str, contents: String) {
    let path = format!("{DIR}{name}");
    std::fs::write(&path, contents + "\n").unwrap();
    println!("wrote {path}");
}
