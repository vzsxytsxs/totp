//! Importing passwords exported by browsers and other password managers
//! (Chrome, Edge, Thorium, Brave, Firefox, Bitwarden, KeePassXC...).

use crate::base32;
use crate::login::{Login, Password};
use crate::otp::{self, Account, Algorithm, OtpKind, Secret};

#[derive(Debug, Default)]
pub struct CsvImport {
    pub logins: Vec<Login>,
    /// 2FA accounts found in a TOTP column; logins point to them via `otp`.
    pub accounts: Vec<Account>,
    /// Rows that were not logins or had nothing usable.
    pub skipped: usize,
}

/// Splits CSV text into rows of fields (RFC 4180: quotes, "" escapes,
/// line breaks inside quotes, CRLF or LF).
pub fn parse_rows(text: &str) -> Vec<Vec<String>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                row.push(std::mem::take(&mut field));
                if !(row.len() == 1 && row[0].is_empty()) {
                    rows.push(std::mem::take(&mut row));
                }
                row.clear();
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

fn column(header: &[String], names: &[&str]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().to_lowercase();
        names.contains(&h.as_str())
    })
}

pub fn import(text: &str) -> Result<CsvImport, String> {
    let rows = parse_rows(text);
    let Some((header, records)) = rows.split_first() else {
        return Err("The file is empty".into());
    };
    let title = column(header, &["name", "title"]);
    let url = column(header, &["url", "login_uri", "website", "uri", "web site", "origin"]);
    let username = column(header, &["username", "login_username", "user name", "user", "email", "login"]);
    let password = column(header, &["password", "login_password"]);
    let notes = column(header, &["note", "notes", "extra", "comments"]);
    let totp = column(header, &["totp", "login_totp", "otp", "otpauth"]);
    let kind = column(header, &["type"]);
    if password.is_none() || (username.is_none() && url.is_none()) {
        return Err(
            "This file does not look like a password export (no \"password\" and \"username\"/\"url\" columns)".into(),
        );
    }

    let mut result = CsvImport::default();
    let now = otp::now_unix() as i64;
    for record in records {
        let get = |i: Option<usize>| i.and_then(|i| record.get(i)).map(|s| s.trim().to_string()).unwrap_or_default();
        let row_type = get(kind).to_lowercase();
        if !row_type.is_empty() && row_type != "login" {
            result.skipped += 1;
            continue;
        }
        let mut login = Login {
            title: get(title),
            url: get(url),
            username: get(username),
            password: Password::new(record.get(password.unwrap()).cloned().unwrap_or_default()),
            notes: get(notes),
            created: now,
            modified: now,
            ..Default::default()
        };
        if login.url.starts_with("chrome://") || login.url.starts_with("about:") {
            login.url.clear();
        }
        if login.title.is_empty() {
            login.title = login.display_title();
        }
        if (login.username.is_empty() && login.password.is_empty()) || login.validate().is_err() {
            result.skipped += 1;
            continue;
        }
        let totp_value = get(totp);
        if !totp_value.is_empty() {
            if let Some(mut account) = totp_account(&totp_value, &login) {
                account.id = crate::crypto::new_id();
                login.otp = account.id.clone();
                result.accounts.push(account);
            }
        }
        result.logins.push(login);
    }
    Ok(result)
}

fn totp_account(value: &str, login: &Login) -> Option<Account> {
    if otp::strip_prefix_ci(value, "otpauth://").is_some() {
        return otp::parse_otpauth(value).ok();
    }
    let secret = base32::decode(value).ok()?;
    let account = Account {
        id: String::new(),
        kind: OtpKind::Totp,
        issuer: login.display_title(),
        name: login.username.clone(),
        secret: Secret::new(secret),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        counter: 0,
    };
    account.validate().ok()?;
    Some(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_with_quotes_and_newlines() {
        let rows = parse_rows("\u{feff}a,b,c\r\n\"x, y\",\"say \"\"hi\"\"\",\"multi\nline\"\n\n1,,3");
        assert_eq!(rows, vec![vec!["a", "b", "c"], vec!["x, y", "say \"hi\"", "multi\nline"], vec!["1", "", "3"],]);
    }

    #[test]
    fn chrome_export() {
        let csv = "name,url,username,password,note\n\
                   github.com,https://github.com/login,octocat,\"p,w\"\"1\",\n\
                   ,https://www.example.com/,me@example.com,secret,hello\n\
                   empty,https://x.com,,,\n";
        let r = import(csv).unwrap();
        assert_eq!(r.logins.len(), 2);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.logins[0].password.as_str(), "p,w\"1");
        assert_eq!(r.logins[1].title, "example.com");
        assert_eq!(r.logins[1].notes, "hello");
    }

    #[test]
    fn firefox_and_bitwarden_exports() {
        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                       \"https://accounts.google.com\",\"me@gmail.com\",\"pw\",,\"https://accounts.google.com\",\"{a}\",\"1\",\"1\",\"1\"\n";
        let r = import(firefox).unwrap();
        assert_eq!(r.logins[0].title, "accounts.google.com");
        assert_eq!(r.logins[0].username, "me@gmail.com");

        let bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                         ,,login,GitHub,,,0,https://github.com,octo,pw1,JBSWY3DPEHPK3PXP\n\
                         ,,note,Secret note,text,,0,,,,\n\
                         ,,login,Site,,,0,https://site.com,me,pw2,otpauth://totp/Site:me?secret=GEZDGNBVGY3TQOJQ\n";
        let r = import(bitwarden).unwrap();
        assert_eq!(r.logins.len(), 2);
        assert_eq!(r.skipped, 1);
        assert_eq!(r.accounts.len(), 2);
        assert_eq!(r.logins[0].otp, r.accounts[0].id);
        assert_eq!(r.accounts[0].issuer, "GitHub");
        assert_eq!(r.accounts[0].name, "octo");
        assert_eq!(r.accounts[1].issuer, "Site");
    }

    #[test]
    fn rejects_other_files() {
        assert!(import("").is_err());
        assert!(import("a,b,c\n1,2,3").is_err());
    }
}
