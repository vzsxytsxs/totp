//! Saved website logins (password manager) and the rules that decide which
//! logins a web page may see.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A password. Wiped from memory when dropped; never printed by `Debug`.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Password(String);

impl Password {
    pub fn new(text: impl Into<String>) -> Self {
        Password(text.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// One saved login. This is also the JSON shape used in backups (`logins`),
/// shared with the Android app.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: Password,
    pub url: String,
    pub notes: String,
    /// Id of the linked 2FA account, or empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub otp: String,
    /// Unix seconds.
    pub created: i64,
    pub modified: i64,
}

impl Login {
    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() && self.url.trim().is_empty() {
            return Err("A login needs a title or a website".into());
        }
        let too_long = |s: &str, max: usize| s.chars().count() > max;
        if too_long(&self.title, 256)
            || too_long(&self.username, 512)
            || too_long(self.password.as_str(), 4096)
            || too_long(&self.url, 2048)
            || too_long(&self.notes, 65536)
            || too_long(&self.otp, 64)
        {
            return Err("A field is too long".into());
        }
        Ok(())
    }

    /// Title, or the website's host name when there is no title.
    pub fn display_title(&self) -> String {
        if !self.title.trim().is_empty() {
            return self.title.trim().to_string();
        }
        match Site::parse(&self.url) {
            Some(site) => site.host.strip_prefix("www.").unwrap_or(&site.host).to_string(),
            None => self.url.trim().to_string(),
        }
    }

    /// Host shown in lists ("github.com"), or empty.
    pub fn host(&self) -> String {
        Site::parse(&self.url).map(|s| s.host).unwrap_or_default()
    }

    /// Same website, username and password (used to skip duplicates on import).
    pub fn same_as(&self, other: &Login) -> bool {
        self.host() == other.host() && self.username == other.username && self.password == other.password
    }
}

/// Scheme, host and port of a URL, parsed leniently ("github.com" works too).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// Lower case; empty when the text had no scheme.
    pub scheme: String,
    /// Lower case, without a trailing dot. IPv6 addresses keep their brackets.
    pub host: String,
    pub port: Option<u16>,
}

impl Site {
    pub fn parse(text: &str) -> Option<Site> {
        let text = text.trim();
        let (scheme, rest) = match text.find("://") {
            Some(i) if i > 0 && text[..i].chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) => {
                (text[..i].to_ascii_lowercase(), &text[i + 3..])
            }
            _ => (String::new(), text),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let authority = authority.rsplit('@').next().unwrap_or("");
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            let end = after.find(']')?;
            let host = format!("[{}]", &after[..end]);
            let port = after[end + 1..].strip_prefix(':');
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            Some("") | None => None,
            Some(p) => Some(p.parse::<u16>().ok()?),
        };
        let host = host.trim_end_matches('.').to_lowercase();
        if host.is_empty() || host.chars().any(|c| c.is_whitespace() || "\\<>\"'`{}|^%".contains(c)) {
            return None;
        }
        Some(Site { scheme, host, port })
    }

    fn is_ip_or_local(&self) -> bool {
        self.host.starts_with('[')
            || self.host == "localhost"
            || self.host.ends_with(".localhost")
            || self.host.split('.').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    }
}

/// How well a saved login's website matches the page the browser is on.
/// `None` means the page must not see this login at all.
///
/// * Only http(s) pages.
/// * A login saved for `https://` (or without a scheme) is never given to an
///   `http://` page, except for IP addresses and `localhost`.
/// * `example.com` also matches its subdomains (`accounts.example.com`), but
///   never look-alikes (`example.com.evil.net`, `myexample.com`).
/// * A port in the saved address must match.
pub fn match_score(login_url: &str, page_url: &str) -> Option<u8> {
    let page = Site::parse(page_url)?;
    if page.scheme != "https" && page.scheme != "http" {
        return None;
    }
    let login = Site::parse(login_url)?;
    match login.scheme.as_str() {
        "https" if page.scheme == "http" => return None,
        "" if page.scheme == "http" && !login.is_ip_or_local() => return None,
        "" | "http" | "https" => {}
        _ => return None,
    }
    if let Some(port) = login.port {
        let page_port = page.port.unwrap_or(if page.scheme == "https" { 443 } else { 80 });
        if port != page_port {
            return None;
        }
    }
    let saved = login.host.strip_prefix("www.").unwrap_or(&login.host);
    let visited = page.host.strip_prefix("www.").unwrap_or(&page.host);
    if saved == visited {
        return Some(2);
    }
    let subdomain_allowed = saved.contains('.') && !login.is_ip_or_local();
    if subdomain_allowed && visited.len() > saved.len() && visited.ends_with(saved) {
        let boundary = visited.len() - saved.len() - 1;
        if visited.as_bytes()[boundary] == b'.' {
            return Some(1);
        }
    }
    None
}

/// Options for the password generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorOptions {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out characters that are easy to confuse (Il1O0).
    pub avoid_similar: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        GeneratorOptions { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_similar: false }
    }
}

pub const GENERATOR_MIN_LEN: u32 = 4;
pub const GENERATOR_MAX_LEN: u32 = 128;

/// Random password with at least one character of each selected kind.
pub fn generate_password(options: &GeneratorOptions) -> Password {
    const SIMILAR: &str = "Il1O0o";
    let mut sets: Vec<Vec<char>> = Vec::new();
    let mut push = |enabled: bool, chars: &str| {
        if enabled {
            let set: Vec<char> = chars.chars().filter(|c| !options.avoid_similar || !SIMILAR.contains(*c)).collect();
            if !set.is_empty() {
                sets.push(set);
            }
        }
    };
    push(options.lowercase, "abcdefghijklmnopqrstuvwxyz");
    push(options.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    push(options.digits, "0123456789");
    push(options.symbols, "!@#$%^&*()-_=+[]{};:,.?/~");
    if sets.is_empty() {
        sets.push("abcdefghijklmnopqrstuvwxyz".chars().collect());
    }
    let length = options.length.clamp(GENERATOR_MIN_LEN, GENERATOR_MAX_LEN) as usize;
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let mut chars: Vec<char> = Vec::with_capacity(length);
    // One from each set first, then the rest from everything, then shuffle.
    for set in &sets {
        chars.push(set[random_below(set.len())]);
    }
    while chars.len() < length {
        chars.push(all[random_below(all.len())]);
    }
    for i in (1..chars.len()).rev() {
        chars.swap(i, random_below(i + 1));
    }
    let password = Password::new(chars.iter().collect::<String>());
    chars.zeroize();
    password
}

/// Uniform random number in `0..n` (rejection sampling, no modulo bias).
fn random_below(n: usize) -> usize {
    assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = u32::from_le_bytes(crate::crypto::random::<4>());
        if v < zone {
            return (v % n) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_parsing() {
        let s = Site::parse("HTTPS://User:pw@Accounts.Example.COM.:8443/path?q#x").unwrap();
        assert_eq!((s.scheme.as_str(), s.host.as_str(), s.port), ("https", "accounts.example.com", Some(8443)));
        let s = Site::parse("github.com/login").unwrap();
        assert_eq!((s.scheme.as_str(), s.host.as_str(), s.port), ("", "github.com", None));
        let s = Site::parse("http://[::1]:8080/").unwrap();
        assert_eq!((s.host.as_str(), s.port), ("[::1]", Some(8080)));
        assert!(Site::parse("").is_none());
        assert!(Site::parse("https://").is_none());
        assert!(Site::parse("https://exa mple.com").is_none());
        assert!(Site::parse("https://example.com:99999").is_none());
    }

    #[test]
    fn matching_rules() {
        let m = match_score;
        assert_eq!(m("https://github.com", "https://github.com/login"), Some(2));
        assert_eq!(m("github.com", "https://github.com/login"), Some(2));
        assert_eq!(m("https://www.github.com", "https://github.com/"), Some(2));
        assert_eq!(m("github.com", "https://www.github.com/"), Some(2));
        assert_eq!(m("google.com", "https://accounts.google.com/signin"), Some(1));
        // Look-alikes and parents never match.
        assert_eq!(m("github.com", "https://github.com.evil.net/"), None);
        assert_eq!(m("github.com", "https://evilgithub.com/"), None);
        assert_eq!(m("accounts.google.com", "https://google.com/"), None);
        assert_eq!(m("accounts.google.com", "https://mail.google.com/"), None);
        // https logins are not given to http pages.
        assert_eq!(m("https://bank.com", "http://bank.com/"), None);
        assert_eq!(m("bank.com", "http://bank.com/"), None);
        assert_eq!(m("http://old.site", "http://old.site/"), Some(2));
        assert_eq!(m("http://old.site", "https://old.site/"), Some(2));
        // Local devices over http.
        assert_eq!(m("192.168.0.1", "http://192.168.0.1/admin"), Some(2));
        assert_eq!(m("192.168.0.1", "http://10.192.168.0.1/"), None);
        assert_eq!(m("localhost:8080", "http://localhost:8080/"), Some(2));
        assert_eq!(m("localhost:8080", "http://localhost:3000/"), None);
        // Ports.
        assert_eq!(m("https://example.com:443", "https://example.com/"), Some(2));
        assert_eq!(m("https://example.com:8443", "https://example.com/"), None);
        assert_eq!(m("example.com", "https://example.com:8443/"), Some(2));
        // Single-label hosts do not match "subdomains" (would cover a whole TLD).
        assert_eq!(m("com", "https://github.com/"), None);
        // Non-web pages and schemes.
        assert_eq!(m("github.com", "chrome://settings"), None);
        assert_eq!(m("github.com", "file:///C:/github.com/x.html"), None);
        assert_eq!(m("ftp://github.com", "https://github.com/"), None);
        assert_eq!(m("", "https://github.com/"), None);
    }

    #[test]
    fn display_title_and_validation() {
        let mut l = Login { url: "https://www.github.com/login".into(), ..Default::default() };
        assert_eq!(l.display_title(), "github.com");
        assert!(l.validate().is_ok());
        l.title = "  Work GitHub ".into();
        assert_eq!(l.display_title(), "Work GitHub");
        assert!(Login::default().validate().is_err());
        let json = serde_json::to_string(&Login { title: "x".into(), password: Password::new("p"), ..Default::default() }).unwrap();
        assert!(json.contains("\"password\":\"p\"") && !json.contains("\"otp\""));
        assert!(!format!("{:?}", Password::new("hunter2")).contains("hunter2"));
    }

    #[test]
    fn generator() {
        let opts = GeneratorOptions::default();
        for _ in 0..200 {
            let p = generate_password(&opts);
            let s = p.as_str();
            assert_eq!(s.chars().count(), 20);
            assert!(s.chars().any(|c| c.is_ascii_lowercase()));
            assert!(s.chars().any(|c| c.is_ascii_uppercase()));
            assert!(s.chars().any(|c| c.is_ascii_digit()));
            assert!(s.chars().any(|c| !c.is_ascii_alphanumeric()));
        }
        let digits_only = GeneratorOptions { length: 6, lowercase: false, uppercase: false, symbols: false, ..opts };
        assert!(generate_password(&digits_only).as_str().chars().all(|c| c.is_ascii_digit()));
        let none = GeneratorOptions { lowercase: false, uppercase: false, digits: false, symbols: false, length: 1, ..opts };
        assert_eq!(generate_password(&none).as_str().len(), GENERATOR_MIN_LEN as usize);
        let similar = GeneratorOptions { avoid_similar: true, length: 128, ..opts };
        assert!(!generate_password(&similar).as_str().contains(['I', 'l', '1', 'O', '0', 'o']));
        assert_ne!(generate_password(&opts), generate_password(&opts));
    }
}
