//! Checks the shared test vectors in `docs/test-vectors` (also used by the
//! Android test suite), so both apps stay compatible.

use authenticator::otp::Account;
use authenticator::{backup, migration, otp};
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/test-vectors/");

fn vectors() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{DIR}vectors.json")).unwrap()).unwrap()
}

fn account(v: &Value) -> Account {
    serde_json::from_value(v.clone()).unwrap()
}

#[test]
fn totp_and_hotp() {
    let v = vectors();
    for case in v["totp"].as_array().unwrap() {
        let a = account(&serde_json::json!({
            "type": "totp", "secret": case["secret"], "algorithm": case["algorithm"],
            "digits": case["digits"], "period": case["period"]
        }));
        assert_eq!(a.code_at(case["time"].as_u64().unwrap()), case["code"].as_str().unwrap(), "{case}");
    }
    for case in v["hotp"].as_array().unwrap() {
        let a = account(&serde_json::json!({
            "type": "hotp", "secret": case["secret"], "counter": case["counter"]
        }));
        assert_eq!(a.code_at(0), case["code"].as_str().unwrap(), "{case}");
    }
}

#[test]
fn otpauth_uris() {
    let v = vectors();
    for case in v["otpauth"].as_array().unwrap() {
        let parsed = otp::parse_otpauth(case["uri"].as_str().unwrap()).unwrap();
        assert_eq!(parsed, account(&case["account"]), "{}", case["uri"]);
    }
    for uri in v["otpauth_invalid"].as_array().unwrap() {
        assert!(otp::parse_otpauth(uri.as_str().unwrap()).is_err(), "{uri} should be rejected");
    }
}

#[test]
fn google_migration() {
    let v = vectors();
    let batch = migration::decode_uri(v["migration"]["uri"].as_str().unwrap()).unwrap();
    let expected: Vec<Account> = v["migration"]["accounts"].as_array().unwrap().iter().map(account).collect();
    assert_eq!(batch.accounts, expected);
}

#[test]
fn backups_from_both_platforms() {
    let v = vectors();
    for case in v["backups"].as_array().unwrap() {
        let path = format!("{DIR}{}", case["file"].as_str().unwrap());
        let Ok(bytes) = std::fs::read(&path) else {
            panic!("missing fixture {path}");
        };
        let (accounts, invalid) = backup::open(&bytes, case["password"].as_str().unwrap()).unwrap();
        let expected: Vec<Account> = case["accounts"].as_array().unwrap().iter().map(account).collect();
        assert_eq!(accounts, expected, "{path}");
        assert_eq!(invalid, 0);
        assert!(backup::open(&bytes, "wrong password").is_err());
    }
}
