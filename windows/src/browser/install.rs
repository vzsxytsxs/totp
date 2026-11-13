//! Installing the browser side: the extension files (loaded with "Load
//! unpacked"), the native messaging host and its registration with the
//! browsers. Nothing is downloaded; everything is inside this program.

use std::path::{Path, PathBuf};

use super::{HOST_NAME, extension_origin};

/// Extension files, embedded at build time (folder `browser-extension/`).
const EXTENSION_FILES: &[(&str, &[u8])] = &[
    ("manifest.json", include_bytes!("../../../browser-extension/manifest.json")),
    ("background.js", include_bytes!("../../../browser-extension/background.js")),
    ("protocol.js", include_bytes!("../../../browser-extension/protocol.js")),
    ("fill.js", include_bytes!("../../../browser-extension/fill.js")),
    ("popup.html", include_bytes!("../../../browser-extension/popup.html")),
    ("popup.js", include_bytes!("../../../browser-extension/popup.js")),
    ("options.html", include_bytes!("../../../browser-extension/options.html")),
    ("options.js", include_bytes!("../../../browser-extension/options.js")),
    ("style.css", include_bytes!("../../../browser-extension/style.css")),
    ("icons/16.png", include_bytes!("../../../browser-extension/icons/16.png")),
    ("icons/32.png", include_bytes!("../../../browser-extension/icons/32.png")),
    ("icons/48.png", include_bytes!("../../../browser-extension/icons/48.png")),
    ("icons/128.png", include_bytes!("../../../browser-extension/icons/128.png")),
];

/// Registry keys (under HKEY_CURRENT_USER) where Chromium-based browsers look
/// for native messaging hosts.
#[cfg(windows)]
const BROWSER_KEYS: &[&str] = &[
    r"Software\Google\Chrome",
    r"Software\Chromium",
    r"Software\Thorium",
    r"Software\Microsoft\Edge",
    r"Software\BraveSoftware\Brave-Browser",
    r"Software\Vivaldi",
];

pub struct Paths {
    pub root: PathBuf,
    /// Folder to choose in "Load unpacked".
    pub extension: PathBuf,
    pub host: PathBuf,
    pub manifest: PathBuf,
}

pub fn paths() -> Paths {
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA")
        .map(|dir| PathBuf::from(dir).join("Authenticator"))
        .unwrap_or_else(crate::platform::data_dir)
        .join("browser");
    #[cfg(not(windows))]
    let root = crate::platform::data_dir().join("browser");
    Paths {
        extension: root.join("extension"),
        host: root.join(if cfg!(windows) { "authenticator-host.exe" } else { "authenticator-host" }),
        manifest: root.join(format!("{HOST_NAME}.json")),
        root,
    }
}

/// Writes `data` unless the file already has exactly that content.
fn write_if_changed(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).is_ok_and(|current| current == data) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, data)
}

fn extract_extension(paths: &Paths) -> std::io::Result<()> {
    for (name, data) in EXTENSION_FILES {
        write_if_changed(&paths.extension.join(name), data)?;
    }
    Ok(())
}

/// The host is a copy of this program marked as a console program, so that
/// browsers can talk to it through its standard input and output.
#[cfg(windows)]
fn host_image() -> Result<Vec<u8>, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut image = std::fs::read(&exe).map_err(|e| e.to_string())?;
    set_console_subsystem(&mut image)?;
    Ok(image)
}

/// Changes the PE "subsystem" field from GUI (2) to console (3).
pub fn set_console_subsystem(image: &mut [u8]) -> Result<(), String> {
    let bad = || "Unexpected program file format".to_string();
    if image.get(..2) != Some(b"MZ") {
        return Err(bad());
    }
    let pe = u32::from_le_bytes(image.get(0x3c..0x40).ok_or_else(bad)?.try_into().map_err(|_| bad())?) as usize;
    if image.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err(bad());
    }
    // COFF header (20 bytes) after the signature, then the optional header,
    // where Subsystem is at offset 68 for both PE32 and PE32+.
    let field = pe + 4 + 20 + 68;
    let subsystem = image.get_mut(field..field + 2).ok_or_else(bad)?;
    match u16::from_le_bytes([subsystem[0], subsystem[1]]) {
        2 | 3 => {
            subsystem.copy_from_slice(&3u16.to_le_bytes());
            Ok(())
        }
        _ => Err(bad()),
    }
}

fn host_manifest(host: &Path) -> Vec<u8> {
    let manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "Authenticator: fills in saved logins",
        "path": host,
        "type": "stdio",
        "allowed_origins": [extension_origin()],
    });
    serde_json::to_vec_pretty(&manifest).expect("serializable")
}

/// Installs or updates everything. Safe to call on every start.
pub fn install() -> Result<Paths, String> {
    let paths = paths();
    let failed = |what: &str, e: &dyn std::fmt::Display| format!("Could not {what}: {e}");
    extract_extension(&paths).map_err(|e| failed("write the extension files", &e))?;

    #[cfg(windows)]
    {
        let image = host_image()?;
        if let Err(e) = write_if_changed(&paths.host, &image) {
            // The browser may be running the old copy; it is updated next time.
            if !paths.host.exists() {
                return Err(failed("install the browser helper", &e));
            }
        }
        let app = std::env::current_exe().map_err(|e| e.to_string())?;
        write_if_changed(&paths.root.join("app-path.txt"), app.to_string_lossy().as_bytes())
            .map_err(|e| failed("install the browser helper", &e))?;
        write_if_changed(&paths.manifest, &host_manifest(&paths.host))
            .map_err(|e| failed("install the browser helper", &e))?;
        let manifest = paths.manifest.to_string_lossy().into_owned();
        for key in BROWSER_KEYS {
            crate::platform::reg_set(&format!(r"{key}\NativeMessagingHosts\{HOST_NAME}"), None, &manifest)
                .map_err(|e| failed("register the browser helper", &e))?;
        }
    }

    #[cfg(not(windows))]
    {
        // Development: the browser runs this program directly.
        let app = std::env::current_exe().map_err(|e| e.to_string())?;
        write_if_changed(&paths.manifest, &host_manifest(&app)).map_err(|e| failed("write the host manifest", &e))?;
        if let Some(dir) = std::env::var_os("AUTH_DEV_NM_DIR") {
            let target = PathBuf::from(dir).join(format!("{HOST_NAME}.json"));
            write_if_changed(&target, &host_manifest(&app)).map_err(|e| failed("write the host manifest", &e))?;
        }
    }
    Ok(paths)
}

/// Unregisters the host so browsers can no longer start it. The extension
/// folder stays, so a browser that still has it loaded does not complain.
pub fn uninstall() {
    let paths = paths();
    #[cfg(windows)]
    for key in BROWSER_KEYS {
        crate::platform::reg_delete_key(&format!(r"{key}\NativeMessagingHosts\{HOST_NAME}"));
    }
    #[cfg(not(windows))]
    if let Some(dir) = std::env::var_os("AUTH_DEV_NM_DIR") {
        let _ = std::fs::remove_file(PathBuf::from(dir).join(format!("{HOST_NAME}.json")));
    }
    let _ = std::fs::remove_file(&paths.manifest);
    let _ = std::fs::remove_file(paths.root.join("app-path.txt"));
    let _ = std::fs::remove_file(&paths.host);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pe(subsystem: u16) -> Vec<u8> {
        let mut image = vec![0u8; 512];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        let field = 0x80 + 4 + 20 + 68;
        image[field..field + 2].copy_from_slice(&subsystem.to_le_bytes());
        image
    }

    #[test]
    fn patches_the_subsystem() {
        let mut image = fake_pe(2);
        set_console_subsystem(&mut image).unwrap();
        assert_eq!(image, fake_pe(3));
        assert!(set_console_subsystem(&mut fake_pe(10)).is_err());
        assert!(set_console_subsystem(&mut b"not a program".to_vec()).is_err());
        assert!(set_console_subsystem(&mut b"MZ".to_vec()).is_err());
    }

    #[test]
    fn manifest_names_the_extension() {
        let manifest: serde_json::Value = serde_json::from_slice(&host_manifest(Path::new("/x/host"))).unwrap();
        assert_eq!(manifest["name"], HOST_NAME);
        assert_eq!(manifest["allowed_origins"][0], "chrome-extension://camkpchgligkkfchbhidopnijiipaikm/");
    }

    #[test]
    fn embedded_extension_matches_the_fixed_id() {
        let manifest = EXTENSION_FILES.iter().find(|(name, _)| *name == "manifest.json").unwrap().1;
        let manifest: serde_json::Value = serde_json::from_slice(manifest).unwrap();
        let key = manifest["key"].as_str().unwrap();
        use base64::Engine;
        use sha2::Digest;
        let der = base64::engine::general_purpose::STANDARD.decode(key).unwrap();
        let hash = sha2::Sha256::digest(&der);
        let id: String =
            hash[..16].iter().flat_map(|b| [b >> 4, b & 15]).map(|nibble| (b'a' + nibble) as char).collect();
        assert_eq!(id, super::super::EXTENSION_ID);
        assert_eq!(manifest["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
    }
}
