// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use authenticator::otp::{self, Account, Algorithm, OtpKind, Secret};
use authenticator::vault::{self, Vault, VaultError};
use authenticator::{ImportResult, backup, base32, crypto, migration, parse_import_text, platform, qr};
use slint::{ComponentHandle, Model, ModelRc, Timer, TimerMode, VecModel};
use zeroize::Zeroizing;

slint::include_modules!();

const WINDOW_TITLE: &str = "Authenticator";
const AUTO_LOCK_MINUTES: [u32; 5] = [1, 5, 15, 60, 0];
const CLIPBOARD_SECONDS: [u32; 4] = [15, 30, 60, 0];
/// Wrong PINs allowed before the app starts imposing a waiting time.
const FREE_ATTEMPTS: u32 = 5;
const MAX_BACKUP_FILE: u64 = 20 * 1024 * 1024;

struct State {
    vault_path: PathBuf,
    vault: Option<Vault>,
    /// Stable UI ids, parallel to `vault.entries`.
    ids: Vec<i32>,
    next_id: i32,
    /// Indices into `vault.entries` of the rows currently shown.
    visible: Vec<usize>,
    filter: String,
    failed_attempts: u32,
    locked_until: Option<Instant>,
    pending_backup: Option<Vec<u8>>,
    clipboard: Option<arboard::Clipboard>,
    copied: Option<Zeroizing<String>>,
    clipboard_timer: Timer,
    last_second: u64,
    rows: Rc<VecModel<EntryRow>>,
    hwnd: isize,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static TOAST_TIMER: Timer = Timer::default();
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow_mut().as_mut().expect("state not initialised")))
}

/// Like `with_state`, but silently skips if the state is busy (timers).
fn try_with_state(f: impl FnOnce(&mut State)) {
    STATE.with(|cell| {
        if let Ok(mut guard) = cell.try_borrow_mut() {
            if let Some(state) = guard.as_mut() {
                f(state);
            }
        }
    });
}

fn main() -> Result<(), slint::PlatformError> {
    if !platform::acquire_single_instance(WINDOW_TITLE) {
        return Ok(());
    }
    let ui = AppWindow::new()?;
    let vault_path = vault::default_path();
    let rows = Rc::new(VecModel::<EntryRow>::default());
    ui.set_entries(ModelRc::from(rows.clone()));
    ui.set_version(env!("CARGO_PKG_VERSION").into());
    ui.set_data_path(vault_path.display().to_string().into());
    ui.set_can_scan_screen(cfg!(windows));
    ui.set_page(if vault::exists(&vault_path) { Page::Lock } else { Page::Setup });

    STATE.with(|cell| {
        *cell.borrow_mut() = Some(State {
            vault_path,
            vault: None,
            ids: Vec::new(),
            next_id: 0,
            visible: Vec::new(),
            filter: String::new(),
            failed_attempts: 0,
            locked_until: None,
            pending_backup: None,
            clipboard: None,
            copied: None,
            clipboard_timer: Timer::default(),
            last_second: 0,
            rows,
            hwnd: 0,
        })
    });

    wire_callbacks(&ui);

    let ticker = Timer::default();
    let weak = ui.as_weak();
    ticker.start(TimerMode::Repeated, Duration::from_millis(250), move || {
        if let Some(ui) = weak.upgrade() {
            tick(&ui);
        }
    });

    ui.run()?;

    try_with_state(|s| {
        clear_clipboard_if_ours(s);
        s.vault = None;
    });
    Ok(())
}

// ------------------------------------------------------------------ helpers

fn tick(ui: &AppWindow) {
    try_with_state(|s| {
        if s.hwnd == 0 {
            s.hwnd = native_handle(ui);
            if s.hwnd != 0 {
                let hide = s.vault.as_ref().map(|v| v.settings.hide_from_capture).unwrap_or(true);
                platform::set_capture_protection(s.hwnd, hide);
            }
        }
        let Some(vault) = s.vault.as_ref() else { return };
        let minutes = vault.settings.auto_lock_minutes;
        if minutes > 0 && !ui.get_busy() {
            if let Some(idle) = platform::idle_seconds() {
                if idle >= minutes as u64 * 60 {
                    lock_now(ui, s);
                    return;
                }
            }
        }
        let now = otp::now_unix();
        if now != s.last_second && ui.get_page() == Page::List {
            s.last_second = now;
            update_codes(s, now);
        }
    });
}

#[cfg(windows)]
fn native_handle(ui: &AppWindow) -> isize {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match ui.window().window_handle().window_handle() {
        Ok(handle) => match handle.as_raw() {
            RawWindowHandle::Win32(h) => h.hwnd.get(),
            _ => 0,
        },
        Err(_) => 0,
    }
}

#[cfg(not(windows))]
fn native_handle(_ui: &AppWindow) -> isize {
    0
}

fn format_code(code: &str) -> String {
    match code.len() {
        6 | 7 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_string(),
    }
}

fn make_row(id: i32, account: &Account, now: u64) -> EntryRow {
    let totp = account.kind == OtpKind::Totp;
    let remaining = if totp { account.seconds_remaining(now) as i32 } else { 0 };
    let (title, subtitle) = if account.issuer.is_empty() {
        (account.display_title(), String::new())
    } else {
        (account.issuer.clone(), account.name.clone())
    };
    EntryRow {
        id,
        title: title.into(),
        subtitle: subtitle.into(),
        issuer: account.issuer.as_str().into(),
        name: account.name.as_str().into(),
        code: format_code(&account.code_at(now)).into(),
        remaining,
        progress: if totp { remaining as f32 / account.period.max(1) as f32 } else { 0.0 },
        hotp: !totp,
        warn: totp && remaining <= 5,
    }
}

fn refresh_list(ui: &AppWindow, s: &mut State) {
    let now = otp::now_unix();
    let filter = s.filter.trim().to_lowercase();
    let (rows, total) = match s.vault.as_ref() {
        Some(vault) => {
            s.visible = vault
                .entries
                .iter()
                .enumerate()
                .filter(|(_, a)| {
                    filter.is_empty()
                        || a.issuer.to_lowercase().contains(&filter)
                        || a.name.to_lowercase().contains(&filter)
                })
                .map(|(i, _)| i)
                .collect();
            let rows: Vec<EntryRow> =
                s.visible.iter().map(|&i| make_row(s.ids[i], &vault.entries[i], now)).collect();
            (rows, vault.entries.len())
        }
        None => {
            s.visible.clear();
            (Vec::new(), 0)
        }
    };
    s.rows.set_vec(rows);
    s.last_second = now;
    ui.set_total_entries(total as i32);
}

fn update_codes(s: &State, now: u64) {
    let Some(vault) = s.vault.as_ref() else { return };
    for (row, &index) in s.visible.iter().enumerate() {
        let Some(account) = vault.entries.get(index) else { continue };
        let fresh = make_row(s.ids[index], account, now);
        if s.rows.row_data(row).as_ref() != Some(&fresh) {
            s.rows.set_row_data(row, fresh);
        }
    }
}

fn set_busy(ui: &AppWindow, text: &str) {
    ui.set_busy_text(text.into());
    ui.set_busy(true);
}

fn toast(ui: &AppWindow, text: impl Into<String>) {
    ui.set_toast_text(text.into().into());
    ui.set_toast_visible(true);
    let weak = ui.as_weak();
    TOAST_TIMER.with(|t| {
        t.start(TimerMode::SingleShot, Duration::from_millis(2800), move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_toast_visible(false);
            }
        })
    });
}

/// Shows a message in the current page's status line, or as a toast on pages without one.
fn report(ui: &AppWindow, error: bool, text: impl Into<String>) {
    let text = text.into();
    match ui.get_page() {
        Page::Add | Page::Export | Page::Settings => {
            // The status line sits at the top of a scrollable page; a toast
            // makes sure the message is seen wherever the user scrolled.
            toast(ui, text.lines().next().unwrap_or_default());
            ui.set_status_error(error);
            ui.set_status_text(text.into());
        }
        _ => toast(ui, text),
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
}

fn save(ui: &AppWindow, s: &State) -> bool {
    match s.vault.as_ref().map(|v| v.save()) {
        Some(Err(e)) => {
            report(ui, true, format!("Could not save: {e}"));
            false
        }
        _ => true,
    }
}

fn index_of(s: &State, id: i32) -> Option<usize> {
    s.ids.iter().position(|&x| x == id)
}

fn clipboard(s: &mut State) -> Result<&mut arboard::Clipboard, String> {
    if s.clipboard.is_none() {
        s.clipboard = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
    }
    Ok(s.clipboard.as_mut().expect("just created"))
}

fn set_clipboard_secret(s: &mut State, text: &str) -> Result<(), String> {
    let cb = clipboard(s)?;
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        // Keep codes out of Windows clipboard history and cloud clipboard.
        cb.set().exclude_from_monitoring().text(text.to_string()).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        cb.set_text(text.to_string()).map_err(|e| e.to_string())
    }
}

fn clear_clipboard_if_ours(s: &mut State) {
    if let Some(copied) = s.copied.take() {
        if let Ok(cb) = clipboard(s) {
            if cb.get_text().map(|t| t == *copied).unwrap_or(false) {
                let _ = cb.clear();
            }
        }
    }
}

fn lock_now(ui: &AppWindow, s: &mut State) {
    clear_clipboard_if_ours(s);
    s.vault = None;
    s.ids.clear();
    s.filter.clear();
    s.pending_backup = None;
    refresh_list(ui, s);
    ui.set_search("".into());
    ui.set_export_qrs(ModelRc::default());
    ui.set_edit_id(-1);
    ui.set_restore_dialog(false);
    ui.set_status_text("".into());
    ui.set_lock_error("".into());
    ui.set_page(Page::Lock);
}

fn open_vault(ui: &AppWindow, s: &mut State, vault: Vault) {
    s.ids = (0..vault.entries.len())
        .map(|_| {
            s.next_id += 1;
            s.next_id
        })
        .collect();
    let settings = &vault.settings;
    ui.set_auto_lock_index(AUTO_LOCK_MINUTES.iter().position(|&m| m == settings.auto_lock_minutes).unwrap_or(1) as i32);
    ui.set_clipboard_index(
        CLIPBOARD_SECONDS.iter().position(|&m| m == settings.clipboard_clear_seconds).unwrap_or(1) as i32,
    );
    ui.set_hide_from_capture(settings.hide_from_capture);
    platform::set_capture_protection(s.hwnd, settings.hide_from_capture);
    s.vault = Some(vault);
    s.filter.clear();
    ui.set_search("".into());
    refresh_list(ui, s);
    ui.set_lock_error("".into());
    ui.set_status_text("".into());
    ui.set_page(Page::List);
}

fn today() -> String {
    // Civil date from days since the epoch (H. Hinnant's algorithm), UTC.
    let z = (otp::now_unix() / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

fn qr_image(text: &str) -> Option<slint::Image> {
    let bitmap = qr::encode(text).ok()?;
    let scale = (720 / bitmap.size).max(1);
    let side = bitmap.size * scale;
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(side as u32, side as u32);
    let pixels = buffer.make_mut_slice();
    for y in 0..side {
        for x in 0..side {
            let dark = bitmap.dark[(y / scale) * bitmap.size + x / scale];
            let v = if dark { 0 } else { 255 };
            pixels[y * side + x] = slint::Rgb8Pixel { r: v, g: v, b: v };
        }
    }
    Some(slint::Image::from_rgb8(buffer))
}

// ------------------------------------------------------------------ file dialogs

#[cfg(windows)]
mod dialogs {
    use super::AppWindow;
    use slint::ComponentHandle;
    use std::path::PathBuf;

    fn base(ui: &AppWindow, title: &str) -> rfd::FileDialog {
        rfd::FileDialog::new().set_parent(&ui.window().window_handle()).set_title(title)
    }
    pub fn open_image(ui: &AppWindow) -> Option<PathBuf> {
        base(ui, "Open QR code image")
            .add_filter("Images", &["png", "jpg", "jpeg", "bmp", "gif", "webp"])
            .pick_file()
    }
    pub fn open_backup(ui: &AppWindow) -> Option<PathBuf> {
        base(ui, "Open backup file")
            .add_filter("Authenticator backup", &["json"])
            .add_filter("All files", &["*"])
            .pick_file()
    }
    pub fn save_backup(ui: &AppWindow, name: &str) -> Option<PathBuf> {
        base(ui, "Save backup file")
            .set_file_name(name)
            .add_filter("Authenticator backup", &["json"])
            .save_file()
    }
}

/// Development fallback: paths come from environment variables.
#[cfg(not(windows))]
mod dialogs {
    use super::AppWindow;
    use std::path::PathBuf;

    pub fn open_image(_: &AppWindow) -> Option<PathBuf> {
        std::env::var_os("AUTH_DEV_IMAGE").map(PathBuf::from)
    }
    pub fn open_backup(_: &AppWindow) -> Option<PathBuf> {
        std::env::var_os("AUTH_DEV_BACKUP").map(PathBuf::from)
    }
    pub fn save_backup(_: &AppWindow, name: &str) -> Option<PathBuf> {
        Some(std::env::temp_dir().join(name))
    }
}

// ------------------------------------------------------------------ importing

fn import_accounts(ui: &AppWindow, accounts: Vec<Account>, messages: Vec<String>, batch: Option<(u32, u32)>) {
    with_state(|s| {
        let Some(vault) = s.vault.as_mut() else { return };
        let (mut added, mut duplicates) = (0usize, 0usize);
        for account in accounts {
            if vault.entries.iter().any(|e| e.same_as(&account)) {
                duplicates += 1;
                continue;
            }
            vault.entries.push(account);
            s.next_id += 1;
            s.ids.push(s.next_id);
            added += 1;
        }
        let saved = added == 0 || save(ui, s);
        refresh_list(ui, s);
        if !saved {
            return;
        }

        let mut text = match (added, duplicates) {
            (0, 0) => "Nothing to add.".to_string(),
            (0, d) => format!("{} already in the list.", if d == 1 { "This account is".into() } else { format!("All {d} accounts are") }),
            (a, 0) => format!("Added {}.", plural(a, "account")),
            (a, d) => format!("Added {} ({} already in the list).", plural(a, "account"), d),
        };
        for message in &messages {
            text.push_str(&format!("\nSkipped {message}"));
        }

        if let Some((index, size)) = batch {
            if index < size {
                ui.set_page(Page::Add);
                ui.set_status_error(false);
                ui.set_status_text(
                    format!("{text}\nThat was QR code {index} of {size} from Google Authenticator. Now add code {}.", index + 1)
                        .into(),
                );
                return;
            }
        }
        if added > 0 && messages.is_empty() {
            ui.set_page(Page::List);
            toast(ui, text);
        } else {
            report(ui, added == 0 && duplicates == 0, text);
        }
    });
}

fn import_texts(ui: &AppWindow, texts: Vec<String>) {
    let mut combined = ImportResult::default();
    let mut errors = Vec::new();
    for text in texts {
        match parse_import_text(&text) {
            Ok(result) => {
                combined.accounts.extend(result.accounts);
                combined.messages.extend(result.messages);
                if result.batch.is_some() {
                    combined.batch = result.batch;
                }
            }
            Err(e) => errors.push(e),
        }
    }
    if combined.accounts.is_empty() && combined.messages.is_empty() {
        report(ui, true, errors.into_iter().next().unwrap_or_else(|| "No QR code found.".into()));
        return;
    }
    import_accounts(ui, combined.accounts, combined.messages, combined.batch);
}

/// Runs a QR decoding job off the UI thread, then imports what it found.
fn decode_in_background(
    ui: &AppWindow,
    busy_text: &str,
    job: impl FnOnce() -> Result<Vec<String>, String> + Send + 'static,
) {
    set_busy(ui, busy_text);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let result = job();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_busy(false);
            match result {
                Ok(texts) if texts.is_empty() => report(
                    &ui,
                    true,
                    "No QR code found. Make sure the whole QR code is visible and not cut off.",
                ),
                Ok(texts) => import_texts(&ui, texts),
                Err(e) => report(&ui, true, e),
            }
        });
    });
}

enum ClipboardContent {
    Image(usize, usize, Vec<u8>),
    Text(String),
}

fn paste_image(ui: &AppWindow) {
    let content = with_state(|s| -> Result<ClipboardContent, String> {
        let cb = clipboard(s)?;
        if let Ok(img) = cb.get_image() {
            return Ok(ClipboardContent::Image(img.width, img.height, img.bytes.into_owned()));
        }
        cb.get_text().map(ClipboardContent::Text).map_err(|e| e.to_string())
    });
    match content {
        Ok(ClipboardContent::Image(w, h, rgba)) => {
            decode_in_background(ui, "Looking for a QR code…", move || Ok(qr::decode_rgba(w, h, &rgba)))
        }
        Ok(ClipboardContent::Text(text)) if text.trim_start().to_ascii_lowercase().starts_with("otpauth") => {
            import_texts(ui, vec![text])
        }
        _ => report(
            ui,
            true,
            "The clipboard has no picture of a QR code. Press Win+Shift+S, select the QR code, then press Ctrl+V here.",
        ),
    }
}

fn scan_screen(ui: &AppWindow) {
    let hidden_from_capture = with_state(|s| s.vault.as_ref().map(|v| v.settings.hide_from_capture).unwrap_or(true));
    let capture = || match platform::capture_screen() {
        Some(c) => Ok(qr::decode_rgba(c.width, c.height, &c.rgba)),
        None => Err("Could not capture the screen.".to_string()),
    };
    if hidden_from_capture {
        // Our window is invisible to captures, so it cannot cover the QR code.
        decode_in_background(ui, "Scanning the screen…", capture);
    } else {
        ui.window().set_minimized(true);
        let weak = ui.as_weak();
        Timer::single_shot(Duration::from_millis(450), move || {
            let result = capture();
            if let Some(ui) = weak.upgrade() {
                ui.window().set_minimized(false);
                decode_in_background(&ui, "Scanning the screen…", move || result);
            }
        });
    }
}

// ------------------------------------------------------------------ callbacks

fn wire_callbacks(ui: &AppWindow) {
    let weak = ui.as_weak();

    ui.on_create_pin({
        let weak = weak.clone();
        move |pin, confirm| {
            let Some(ui) = weak.upgrade() else { return };
            let pin = Zeroizing::new(pin.to_string());
            if pin.chars().count() < vault::MIN_PIN_LEN {
                ui.set_lock_error(format!("Use at least {} characters.", vault::MIN_PIN_LEN).into());
                return;
            }
            if *pin != confirm.as_str() {
                ui.set_lock_error("The two entries do not match.".into());
                return;
            }
            let path = with_state(|s| s.vault_path.clone());
            set_busy(&ui, "Creating secure storage…");
            let weak = ui.as_weak();
            std::thread::spawn(move || {
                let result = Vault::create(&path, &pin);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    match result {
                        Ok(vault) => with_state(|s| open_vault(&ui, s, vault)),
                        Err(e) => ui.set_lock_error(e.to_string().into()),
                    }
                });
            });
        }
    });

    ui.on_unlock({
        let weak = weak.clone();
        move |pin| {
            let Some(ui) = weak.upgrade() else { return };
            let pin = Zeroizing::new(pin.to_string());
            if pin.is_empty() {
                return;
            }
            let wait = with_state(|s| s.locked_until.and_then(|t| t.checked_duration_since(Instant::now())));
            if let Some(wait) = wait {
                ui.set_lock_error(format!("Too many wrong attempts. Try again in {} s.", wait.as_secs() + 1).into());
                return;
            }
            let path = with_state(|s| s.vault_path.clone());
            set_busy(&ui, "Unlocking…");
            let weak = ui.as_weak();
            std::thread::spawn(move || {
                let result = Vault::unlock(&path, &pin);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    with_state(|s| match result {
                        Ok(vault) => {
                            s.failed_attempts = 0;
                            s.locked_until = None;
                            open_vault(&ui, s, vault);
                        }
                        Err(VaultError::WrongPin) => {
                            s.failed_attempts += 1;
                            let message = if s.failed_attempts >= FREE_ATTEMPTS {
                                let secs = 30u64 << (s.failed_attempts - FREE_ATTEMPTS).min(5);
                                s.locked_until = Some(Instant::now() + Duration::from_secs(secs));
                                format!("Wrong PIN. Too many attempts: wait {secs} s.")
                            } else {
                                "Wrong PIN.".to_string()
                            };
                            ui.set_lock_error(message.into());
                        }
                        Err(e) => ui.set_lock_error(e.to_string().into()),
                    });
                });
            });
        }
    });

    ui.on_reset_all({
        let weak = weak.clone();
        move |confirm| {
            let Some(ui) = weak.upgrade() else { return };
            if confirm != "DELETE" {
                return;
            }
            with_state(|s| match vault::destroy(&s.vault_path) {
                Ok(()) => {
                    s.failed_attempts = 0;
                    s.locked_until = None;
                    ui.set_lock_error("".into());
                    ui.set_page(Page::Setup);
                }
                Err(e) => ui.set_lock_error(format!("Could not delete the data: {e}").into()),
            });
        }
    });

    ui.on_lock({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                with_state(|s| lock_now(&ui, s));
            }
        }
    });

    ui.on_search_changed({
        let weak = weak.clone();
        move |text| {
            if let Some(ui) = weak.upgrade() {
                with_state(|s| {
                    s.filter = text.to_string();
                    refresh_list(&ui, s);
                });
            }
        }
    });

    ui.on_copy_code({
        let weak = weak.clone();
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            with_state(|s| {
                let Some(index) = index_of(s, id) else { return };
                let Some(vault) = s.vault.as_ref() else { return };
                let code = Zeroizing::new(vault.entries[index].code_at(otp::now_unix()));
                let seconds = vault.settings.clipboard_clear_seconds;
                match set_clipboard_secret(s, &code) {
                    Ok(()) => {
                        s.copied = Some(code);
                        if seconds > 0 {
                            s.clipboard_timer.start(TimerMode::SingleShot, Duration::from_secs(seconds as u64), || {
                                try_with_state(clear_clipboard_if_ours)
                            });
                            toast(&ui, format!("Code copied. The clipboard clears in {seconds} s."));
                        } else {
                            toast(&ui, "Code copied.");
                        }
                    }
                    Err(e) => toast(&ui, format!("Could not copy: {e}")),
                }
            });
        }
    });

    ui.on_next_hotp({
        let weak = weak.clone();
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            with_state(|s| {
                let Some(index) = index_of(s, id) else { return };
                if let Some(vault) = s.vault.as_mut() {
                    vault.entries[index].counter += 1;
                }
                save(&ui, s);
                refresh_list(&ui, s);
            });
        }
    });

    ui.on_rename_entry({
        let weak = weak.clone();
        move |id, issuer, name| {
            let Some(ui) = weak.upgrade() else { return };
            with_state(|s| {
                let Some(index) = index_of(s, id) else { return };
                if let Some(vault) = s.vault.as_mut() {
                    let entry = &mut vault.entries[index];
                    entry.issuer = issuer.trim().chars().take(256).collect();
                    entry.name = name.trim().chars().take(256).collect();
                }
                save(&ui, s);
                refresh_list(&ui, s);
            });
        }
    });

    ui.on_delete_entry({
        let weak = weak.clone();
        move |id| {
            let Some(ui) = weak.upgrade() else { return };
            with_state(|s| {
                let Some(index) = index_of(s, id) else { return };
                if let Some(vault) = s.vault.as_mut() {
                    vault.entries.remove(index);
                    s.ids.remove(index);
                }
                if save(&ui, s) {
                    toast(&ui, "Account deleted.");
                }
                refresh_list(&ui, s);
            });
        }
    });

    ui.on_paste_image({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                paste_image(&ui);
            }
        }
    });

    ui.on_scan_screen({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                scan_screen(&ui);
            }
        }
    });

    ui.on_open_image({
        let weak = weak.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(path) = dialogs::open_image(&ui) {
                decode_in_background(&ui, "Looking for a QR code…", move || qr::decode_file(&path));
            }
        }
    });

    ui.on_add_manual({
        let weak = weak.clone();
        move |issuer, name, secret, kind, algorithm, digits, number| {
            let Some(ui) = weak.upgrade() else { return };
            let fail = |text: &str| report(&ui, true, text);
            if issuer.trim().is_empty() && name.trim().is_empty() {
                return fail("Enter the service or account name.");
            }
            let secret = match base32::decode(&secret) {
                Ok(bytes) => bytes,
                Err(e) => return fail(&e),
            };
            let kind = if kind == 1 { OtpKind::Hotp } else { OtpKind::Totp };
            let Ok(number) = number.trim().parse::<u64>() else {
                return fail(if kind == OtpKind::Totp { "The period must be a number of seconds." } else { "The counter must be a number." });
            };
            let account = Account {
                kind,
                issuer: issuer.trim().to_string(),
                name: name.trim().to_string(),
                secret: Secret::new(secret),
                algorithm: [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512][algorithm.clamp(0, 2) as usize],
                digits: [6, 7, 8][digits.clamp(0, 2) as usize],
                period: if kind == OtpKind::Totp { number.min(u32::MAX as u64) as u32 } else { 30 },
                counter: if kind == OtpKind::Hotp { number } else { 0 },
            };
            if let Err(e) = account.validate() {
                return fail(&e);
            }
            import_accounts(&ui, vec![account], Vec::new(), None);
        }
    });

    ui.on_add_link({
        let weak = weak.clone();
        move |text| {
            if let Some(ui) = weak.upgrade() {
                if !text.trim().is_empty() {
                    import_texts(&ui, vec![text.to_string()]);
                }
            }
        }
    });

    ui.on_restore_backup({
        let weak = weak.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let Some(path) = dialogs::open_backup(&ui) else { return };
            let too_big = std::fs::metadata(&path).map(|m| m.len() > MAX_BACKUP_FILE).unwrap_or(false);
            match std::fs::read(&path) {
                _ if too_big => report(&ui, true, "This file is too large to be a backup."),
                Ok(bytes) => {
                    with_state(|s| s.pending_backup = Some(bytes));
                    ui.set_restore_dialog(true);
                }
                Err(e) => report(&ui, true, format!("Could not read the file: {e}")),
            }
        }
    });

    ui.on_cancel_restore({
        let weak = weak.clone();
        move || {
            with_state(|s| s.pending_backup = None);
            if let Some(ui) = weak.upgrade() {
                ui.set_restore_dialog(false);
            }
        }
    });

    ui.on_restore_backup_password({
        let weak = weak.clone();
        move |password| {
            let Some(ui) = weak.upgrade() else { return };
            let Some(bytes) = with_state(|s| s.pending_backup.clone()) else { return };
            let password = Zeroizing::new(password.to_string());
            set_busy(&ui, "Decrypting backup…");
            let weak = ui.as_weak();
            std::thread::spawn(move || {
                let result = backup::open(&bytes, &password);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    match result {
                        Ok((accounts, invalid)) => {
                            with_state(|s| s.pending_backup = None);
                            ui.set_restore_dialog(false);
                            let messages = if invalid > 0 {
                                vec![format!("{} that could not be read.", plural(invalid, "entry"))]
                            } else {
                                Vec::new()
                            };
                            if accounts.is_empty() && invalid == 0 {
                                report(&ui, true, "The backup is empty.");
                            } else {
                                import_accounts(&ui, accounts, messages, None);
                            }
                        }
                        Err(crypto::EnvelopeError::WrongPassword) => {
                            toast(&ui, "Wrong password for this backup.");
                        }
                        Err(e) => {
                            with_state(|s| s.pending_backup = None);
                            ui.set_restore_dialog(false);
                            report(&ui, true, e.to_string());
                        }
                    }
                });
            });
        }
    });

    ui.on_show_export_qr({
        let weak = weak.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            with_state(|s| {
                let Some(vault) = s.vault.as_ref() else { return };
                let exportable: Vec<&Account> = vault.entries.iter().filter(|a| migration::exportable(a)).collect();
                let left_out = vault.entries.len() - exportable.len();
                if exportable.is_empty() {
                    report(
                        &ui,
                        true,
                        "Google Authenticator only supports 30-second codes with 6 or 8 digits. Use an encrypted backup file instead.",
                    );
                    return;
                }
                let batch_id = i32::from_le_bytes(crypto::random::<4>()) & 0x7fff_ffff;
                let uris = migration::encode_uris(&exportable, batch_id);
                let images: Vec<slint::Image> = uris.iter().filter_map(|u| qr_image(u)).collect();
                let mut note = format!("{} in {}.", plural(exportable.len(), "account"), plural(uris.len(), "QR code"));
                if left_out > 0 {
                    note.push_str(&format!(
                        " {} left out (settings Google Authenticator does not support) — use a backup file for those.",
                        plural(left_out, "account")
                    ));
                }
                ui.set_export_note(note.into());
                ui.set_export_qrs(ModelRc::new(VecModel::from(images)));
                ui.set_export_index(0);
                ui.set_page(Page::ExportQr);
            });
        }
    });

    ui.on_close_export_qr({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_export_qrs(ModelRc::default());
                ui.set_status_text("".into());
                ui.set_page(Page::Export);
            }
        }
    });

    ui.on_save_backup({
        let weak = weak.clone();
        move |password, confirm| {
            let Some(ui) = weak.upgrade() else { return };
            let password = Zeroizing::new(password.to_string());
            if password.chars().count() < backup::MIN_PASSWORD_LEN {
                return report(&ui, true, format!("Use a password with at least {} characters.", backup::MIN_PASSWORD_LEN));
            }
            if *password != confirm.as_str() {
                return report(&ui, true, "The two passwords do not match.");
            }
            let Some(path) = dialogs::save_backup(&ui, &format!("authenticator-backup-{}.json", today())) else {
                return;
            };
            let Some(accounts) = with_state(|s| s.vault.as_ref().map(|v| v.entries.clone())) else { return };
            set_busy(&ui, "Encrypting backup…");
            let weak = ui.as_weak();
            std::thread::spawn(move || {
                let result = backup::create(&accounts, &password)
                    .and_then(|contents| std::fs::write(&path, contents).map_err(|e| e.to_string()));
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    match result {
                        Ok(()) => report(
                            &ui,
                            false,
                            format!("Backup of {} saved to {}", plural(accounts.len(), "account"), path.display()),
                        ),
                        Err(e) => report(&ui, true, format!("Could not save the backup: {e}")),
                    }
                });
            });
        }
    });

    ui.on_settings_changed({
        let weak = weak.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            with_state(|s| {
                let Some(vault) = s.vault.as_mut() else { return };
                vault.settings.auto_lock_minutes =
                    AUTO_LOCK_MINUTES[(ui.get_auto_lock_index().max(0) as usize).min(AUTO_LOCK_MINUTES.len() - 1)];
                vault.settings.clipboard_clear_seconds =
                    CLIPBOARD_SECONDS[(ui.get_clipboard_index().max(0) as usize).min(CLIPBOARD_SECONDS.len() - 1)];
                vault.settings.hide_from_capture = ui.get_hide_from_capture();
                platform::set_capture_protection(s.hwnd, vault.settings.hide_from_capture);
                if save(&ui, s) {
                    report(&ui, false, "Settings saved.");
                }
            });
        }
    });

    ui.on_change_pin({
        let weak = weak.clone();
        move |current, new_pin, confirm| {
            let Some(ui) = weak.upgrade() else { return };
            let current = Zeroizing::new(current.to_string());
            let new_pin = Zeroizing::new(new_pin.to_string());
            if new_pin.chars().count() < vault::MIN_PIN_LEN {
                return report(&ui, true, format!("Use at least {} characters.", vault::MIN_PIN_LEN));
            }
            if *new_pin != confirm.as_str() {
                return report(&ui, true, "The new PIN entries do not match.");
            }
            let Some(mut vault) = with_state(|s| s.vault.take()) else { return };
            set_busy(&ui, "Changing PIN…");
            let weak = ui.as_weak();
            std::thread::spawn(move || {
                let result = if vault.verify_pin(&current) {
                    vault.change_pin(&new_pin).map_err(|e| e.to_string())
                } else {
                    Err("The current PIN is wrong.".to_string())
                };
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_busy(false);
                    with_state(|s| s.vault = Some(vault));
                    match result {
                        Ok(()) => report(&ui, false, "PIN changed."),
                        Err(e) => report(&ui, true, e),
                    }
                });
            });
        }
    });
}
