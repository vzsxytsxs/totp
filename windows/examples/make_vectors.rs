//! Regenerates `docs/test-vectors/backup-from-windows.json`, the fixture that
//! the Android test suite must be able to decrypt.
//! Run: cargo run --example make_vectors

use authenticator::backup;
use authenticator::crypto::KdfParams;
use authenticator::otp::parse_otpauth;

fn main() {
    let accounts = vec![
        parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap(),
        parse_otpauth("otpauth://totp/Banco%20%C3%81gil:jo%C3%A3o?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&period=60").unwrap(),
        parse_otpauth("otpauth://hotp/Legacy?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=3").unwrap(),
    ];
    // Small KDF parameters keep the test fast; real backups use the defaults.
    let params = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
    let file = backup::create_with_params(&accounts, "correct horse battery staple ção", &params).unwrap();
    let out = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/test-vectors/backup-from-windows.json");
    std::fs::write(out, file + "\n").unwrap();
    println!("wrote {out}");
}
