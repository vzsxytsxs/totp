//! Preferences that are not secret and are needed while the vault is locked
//! (for example, whether closing the window keeps the app in the
//! notification area). Stored as plain JSON next to the vault.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::platform;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Closing the window hides it to the notification area instead of quitting.
    pub close_to_tray: bool,
    /// The browser extension may connect.
    pub browser_enabled: bool,
    /// The "still running in the notification area" balloon was shown once.
    pub tray_hint_shown: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { close_to_tray: true, browser_enabled: false, tray_hint_shown: false }
    }
}

pub fn path() -> PathBuf {
    platform::data_dir().join("prefs.json")
}

impl Prefs {
    pub fn load() -> Prefs {
        std::fs::read(path()).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).expect("serializable"))?;
        std::fs::rename(tmp, path)
    }
}
