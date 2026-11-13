//! QR decoding (screenshots, image files, screen capture) and encoding
//! (export to Google Authenticator / another device).

/// Finds and decodes every QR code in an RGBA image.
pub fn decode_rgba(width: usize, height: usize, rgba: &[u8]) -> Vec<String> {
    if width == 0 || height == 0 || rgba.len() < width * height * 4 {
        return Vec::new();
    }
    // Composite over white so transparent PNGs decode, then convert to luma.
    let luma: Vec<u8> = rgba
        .chunks_exact(4)
        .map(|p| {
            let y = (p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000;
            let a = p[3] as u32;
            ((y * a + 255 * (255 - a)) / 255) as u8
        })
        .collect();

    let mut found = decode_luma(width, height, &luma, false);
    if found.is_empty() {
        // Dark-mode QR codes (light modules on a dark background).
        found = decode_luma(width, height, &luma, true);
    }
    if found.is_empty() && width * height > 4_000_000 {
        // Very large captures: a half-size pass is faster and often cleaner.
        let (w2, h2) = (width / 2, height / 2);
        let small: Vec<u8> = (0..h2)
            .flat_map(|y| {
                let luma = &luma;
                (0..w2).map(move |x| {
                    let i = 2 * y * width + 2 * x;
                    ((luma[i] as u32 + luma[i + 1] as u32 + luma[i + width] as u32 + luma[i + width + 1] as u32) / 4)
                        as u8
                })
            })
            .collect();
        found = decode_luma(w2, h2, &small, false);
    }
    found
}

fn decode_luma(width: usize, height: usize, luma: &[u8], invert: bool) -> Vec<String> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let v = luma[y * width + x];
        if invert { 255 - v } else { v }
    });
    let mut out: Vec<String> = Vec::new();
    for grid in img.detect_grids() {
        if let Ok((_, content)) = grid.decode() {
            if !out.contains(&content) {
                out.push(content);
            }
        }
    }
    out
}

pub fn decode_file(path: &std::path::Path) -> Result<Vec<String>, String> {
    let img = image::open(path).map_err(|e| format!("Could not open the image: {e}"))?.to_rgba8();
    Ok(decode_rgba(img.width() as usize, img.height() as usize, img.as_raw()))
}

/// QR modules as a square bitmap (true = dark) including a 4-module quiet zone.
pub struct QrBitmap {
    pub size: usize,
    pub dark: Vec<bool>,
}

pub fn encode(text: &str) -> Result<QrBitmap, String> {
    let code =
        qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).map_err(|e| e.to_string())?;
    let n = code.width();
    let colors = code.to_colors();
    let quiet = 4;
    let size = n + 2 * quiet;
    let mut dark = vec![false; size * size];
    for y in 0..n {
        for x in 0..n {
            dark[(y + quiet) * size + x + quiet] = colors[y * n + x] == qrcode::Color::Dark;
        }
    }
    Ok(QrBitmap { size, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders a bitmap the way a screenshot would contain it.
    fn render(bitmap: &QrBitmap, scale: usize, canvas: usize, offset: (usize, usize)) -> Vec<u8> {
        let mut rgba = vec![255u8; canvas * canvas * 4];
        for y in 0..bitmap.size * scale {
            for x in 0..bitmap.size * scale {
                if bitmap.dark[(y / scale) * bitmap.size + x / scale] {
                    let i = ((y + offset.1) * canvas + x + offset.0) * 4;
                    rgba[i..i + 3].copy_from_slice(&[20, 20, 20]);
                }
            }
        }
        rgba
    }

    #[test]
    fn encode_then_decode_in_a_larger_image() {
        let text = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let bitmap = encode(text).unwrap();
        let rgba = render(&bitmap, 4, 600, (130, 70));
        assert_eq!(decode_rgba(600, 600, &rgba), vec![text.to_string()]);
    }

    #[test]
    fn decodes_dense_migration_code() {
        use crate::migration;
        use crate::otp::{Account, Algorithm, OtpKind, Secret};
        let accounts: Vec<Account> = (0..12)
            .map(|i| Account {
                id: String::new(),
                kind: OtpKind::Totp,
                issuer: format!("Service number {i}"),
                name: format!("someone.long.name{i}@example.com"),
                secret: Secret::new(vec![i as u8; 20]),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                counter: 0,
            })
            .collect();
        let refs: Vec<&Account> = accounts.iter().collect();
        for uri in migration::encode_uris(&refs, 7) {
            let bitmap = encode(&uri).unwrap();
            let canvas = bitmap.size * 3 + 40;
            let rgba = render(&bitmap, 3, canvas, (20, 20));
            assert_eq!(decode_rgba(canvas, canvas, &rgba), vec![uri]);
        }
    }
}
