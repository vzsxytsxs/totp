//! RFC 4648 base32 (the encoding used for OTP secrets).

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes without padding, upper case (the form authenticator apps expect).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = ((buffer << 8) | byte as u32) & 0xFFFF;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes a user-supplied secret. Tolerates lower case, spaces, dashes and
/// missing or present `=` padding.
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut seen_padding = false;
    let mut count = 0usize;
    for c in input.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        if c == '=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            return Err("Invalid secret: characters after '=' padding".into());
        }
        let value = match c.to_ascii_uppercase() {
            ch @ 'A'..='Z' => ch as u32 - 'A' as u32,
            ch @ '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => {
                return Err(format!("Invalid character '{c}' in secret (allowed: A-Z, 2-7)"));
            }
        };
        count += 1;
        buffer = ((buffer << 5) | value) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if count == 0 {
        return Err("Secret is empty".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain.as_bytes()), encoded);
            if !plain.is_empty() {
                assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
            }
        }
    }

    #[test]
    fn tolerant_decode() {
        assert_eq!(decode("mzxw 6ytb-oi======").unwrap(), b"foobar");
        assert!(decode("MZXW1").is_err());
        assert!(decode("   ").is_err());
    }
}
