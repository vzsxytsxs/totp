//! Joining imported accounts and logins into the existing ones without
//! creating duplicates (backup restore, CSV import).

use std::collections::{HashMap, HashSet};

use crate::crypto::new_id;
use crate::login::Login;
use crate::otp::{Account, OtpKind, now_unix};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub accounts_added: usize,
    pub accounts_skipped: usize,
    pub logins_added: usize,
    pub logins_updated: usize,
    pub logins_skipped: usize,
}

impl MergeReport {
    /// "2 accounts and 5 passwords added, 1 password updated, 3 already here".
    pub fn summary(&self) -> String {
        let plural = |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let mut added = Vec::new();
        if self.accounts_added > 0 {
            added.push(plural(self.accounts_added, "account", "accounts"));
        }
        if self.logins_added > 0 {
            added.push(plural(self.logins_added, "password", "passwords"));
        }
        let mut parts = Vec::new();
        if !added.is_empty() {
            parts.push(format!("{} added", added.join(" and ")));
        }
        if self.logins_updated > 0 {
            parts.push(format!("{} updated", plural(self.logins_updated, "password", "passwords")));
        }
        let skipped = self.accounts_skipped + self.logins_skipped;
        if skipped > 0 {
            parts.push(format!("{skipped} already here"));
        }
        if parts.is_empty() {
            return "Nothing to import".into();
        }
        let mut text = parts.join(", ");
        text[..1].make_ascii_uppercase();
        text + "."
    }
}

/// Gives every account and login a unique id. Returns true if anything changed.
pub fn ensure_ids(accounts: &mut [Account], logins: &mut [Login]) -> bool {
    let mut changed = false;
    let mut seen = HashSet::new();
    for a in accounts.iter_mut() {
        if a.id.is_empty() || !seen.insert(a.id.clone()) {
            a.id = new_id();
            seen.insert(a.id.clone());
            changed = true;
        }
    }
    let account_ids = seen;
    let mut seen = HashSet::new();
    let now = now_unix() as i64;
    for l in logins.iter_mut() {
        if l.id.is_empty() || !seen.insert(l.id.clone()) {
            l.id = new_id();
            seen.insert(l.id.clone());
            changed = true;
        }
        if !l.otp.is_empty() && !account_ids.contains(&l.otp) {
            l.otp.clear();
            changed = true;
        }
        if l.created == 0 {
            l.created = if l.modified > 0 { l.modified } else { now };
            changed = true;
        }
        if l.modified == 0 {
            l.modified = l.created;
            changed = true;
        }
    }
    changed
}

/// Adds `new_accounts` and `new_logins` to the existing lists.
///
/// * Accounts already present (same id, or same secret and labels) are
///   skipped; for HOTP the higher counter is kept so used codes stay used.
/// * A login with the same id replaces the existing one only if it was
///   edited more recently. Same website + username + password is a duplicate.
/// * Links from logins to 2FA accounts follow the accounts they point to.
pub fn merge(
    accounts: &mut Vec<Account>,
    logins: &mut Vec<Login>,
    new_accounts: Vec<Account>,
    new_logins: Vec<Login>,
) -> MergeReport {
    let mut report = MergeReport::default();
    let mut id_map: HashMap<String, String> = HashMap::new();

    for mut incoming in new_accounts {
        let existing = accounts
            .iter_mut()
            .find(|a| (!incoming.id.is_empty() && a.id == incoming.id) || a.same_as(&incoming));
        if let Some(existing) = existing {
            if existing.kind == OtpKind::Hotp && incoming.kind == OtpKind::Hotp {
                existing.counter = existing.counter.max(incoming.counter);
            }
            if !incoming.id.is_empty() {
                id_map.insert(incoming.id.clone(), existing.id.clone());
            }
            report.accounts_skipped += 1;
            continue;
        }
        let old_id = incoming.id.clone();
        if incoming.id.is_empty() || accounts.iter().any(|a| a.id == incoming.id) {
            incoming.id = new_id();
        }
        if !old_id.is_empty() {
            id_map.insert(old_id, incoming.id.clone());
        }
        accounts.push(incoming);
        report.accounts_added += 1;
    }

    let now = now_unix() as i64;
    for mut incoming in new_logins {
        if !incoming.otp.is_empty() {
            incoming.otp = id_map.get(&incoming.otp).cloned().unwrap_or_else(|| incoming.otp.clone());
            if !accounts.iter().any(|a| a.id == incoming.otp) {
                incoming.otp.clear();
            }
        }
        if incoming.created == 0 {
            incoming.created = now;
        }
        if incoming.modified == 0 {
            incoming.modified = incoming.created;
        }
        if !incoming.id.is_empty() {
            if let Some(existing) = logins.iter_mut().find(|l| l.id == incoming.id) {
                if incoming.modified > existing.modified {
                    *existing = incoming;
                    report.logins_updated += 1;
                } else {
                    report.logins_skipped += 1;
                }
                continue;
            }
        }
        if logins.iter().any(|l| l.same_as(&incoming)) {
            report.logins_skipped += 1;
            continue;
        }
        if incoming.id.is_empty() {
            incoming.id = new_id();
        }
        logins.push(incoming);
        report.logins_added += 1;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login::Password;
    use crate::otp::parse_otpauth;

    fn acc(uri: &str, id: &str) -> Account {
        let mut a = parse_otpauth(uri).unwrap();
        a.id = id.into();
        a
    }

    fn login(id: &str, url: &str, user: &str, pw: &str, modified: i64, otp: &str) -> Login {
        Login {
            id: id.into(),
            url: url.into(),
            username: user.into(),
            password: Password::new(pw),
            modified,
            created: 1,
            otp: otp.into(),
            ..Default::default()
        }
    }

    #[test]
    fn merges_without_duplicates() {
        let mut accounts = vec![acc("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP", "a1")];
        let mut logins = vec![login("l1", "github.com", "me", "old", 100, "a1")];

        let incoming_accounts = vec![
            // Same secret and labels but a different id (added on another device).
            acc("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP", "phone-a1"),
            acc("otpauth://totp/Google:me?secret=GEZDGNBVGY3TQOJQ", "phone-a2"),
        ];
        let incoming_logins = vec![
            login("l1", "github.com", "me", "new", 200, "phone-a1"), // newer edit
            login("l2", "google.com", "me", "pw", 50, "phone-a2"),
            login("", "github.com", "me", "new", 0, ""), // CSV duplicate
            login("l3", "example.com", "x", "y", 10, "missing"),
        ];
        let report = merge(&mut accounts, &mut logins, incoming_accounts, incoming_logins);
        assert_eq!(
            report,
            MergeReport { accounts_added: 1, accounts_skipped: 1, logins_added: 2, logins_updated: 1, logins_skipped: 1 }
        );
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[1].id, "phone-a2");
        assert_eq!(logins[0].password.as_str(), "new");
        assert_eq!(logins[0].otp, "a1", "link follows the existing account");
        assert_eq!(logins[1].otp, "phone-a2");
        assert_eq!(logins[2].otp, "", "dangling link removed");
        assert_eq!(report.summary(), "1 account and 2 passwords added, 1 password updated, 2 already here.");

        // Importing an older copy changes nothing.
        let older = vec![login("l1", "github.com", "me", "older", 150, "")];
        let report = merge(&mut accounts, &mut logins, vec![], older);
        assert_eq!(report.logins_skipped, 1);
        assert_eq!(logins[0].password.as_str(), "new");
    }

    #[test]
    fn hotp_keeps_highest_counter_and_ids_are_unique() {
        let mut accounts = vec![acc("otpauth://hotp/T?secret=GEZDGNBVGY3TQOJQ&counter=5", "h")];
        let mut logins = Vec::new();
        merge(&mut accounts, &mut logins, vec![acc("otpauth://hotp/T?secret=GEZDGNBVGY3TQOJQ&counter=9", "")], vec![]);
        assert_eq!(accounts[0].counter, 9);
        // Same id = same account, even if it was renamed on the other device.
        let r = merge(&mut accounts, &mut logins, vec![acc("otpauth://hotp/Renamed?secret=GEZDGNBVGY3TQOJQ&counter=1", "h")], vec![]);
        assert_eq!((r.accounts_skipped, accounts.len(), accounts[0].name.as_str()), (1, 1, "T"));

        let mut accounts = vec![acc("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP", ""), acc("otpauth://totp/B?secret=GEZDGNBVGY3TQOJQ", "")];
        let mut logins = vec![login("", "a.com", "u", "p", 0, "nope")];
        assert!(ensure_ids(&mut accounts, &mut logins));
        assert!(accounts.iter().all(|a| a.id.len() == 32) && accounts[0].id != accounts[1].id);
        assert!(!logins[0].id.is_empty() && logins[0].otp.is_empty() && logins[0].created > 0);
        assert!(!ensure_ids(&mut accounts, &mut logins));
    }
}
