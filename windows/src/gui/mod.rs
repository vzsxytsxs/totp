//! The desktop window: shared state, helpers and wiring of the Slint callbacks.
//!
//! The UI itself is in `ui/app.slint`; everything it shows comes from the
//! `App` global. Each submodule handles one area of the window.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use authenticator::otp;
use authenticator::platform;
use authenticator::prefs::Prefs;
use authenticator::vault::{self, Vault};
use slint::{ComponentHandle, Model, ModelRc, Timer, TimerMode, VecModel};
use zeroize::Zeroizing;

slint::include_modules!();

/// Connects a Slint callback of the `App` global to a closure that gets the
/// window. Every callback also counts as "the app is being used" for auto-lock.
macro_rules! callback {
    ($ui:expr, $name:ident, |$u:ident $(, $arg:pat_param)*| $body:expr) => {{
        let weak = $ui.as_weak();
        $crate::gui::app($ui).$name(move |$($arg),*| {
            if let Some($u) = weak.upgrade() {
                $crate::gui::touch();
                let _: () = $body;
            }
        });
    }};
}

mod browser;
mod codes;
mod logins;
mod session;
mod transfer;
mod window;

pub const WINDOW_TITLE: &str = "Authenticator";
pub const AUTO_LOCK_MINUTES: [u32; 5] = [1, 5, 15, 60, 0];
pub const CLIPBOARD_SECONDS: [u32; 4] = [15, 30, 60, 0];

/// What to do once the PIN has been confirmed again.
#[derive(Clone, Copy, Debug)]
pub enum Pending {
    Export,
    CodeQr(i32),
}

pub struct State {
    pub vault_path: PathBuf,
    pub vault: Option<Vault>,
    pub prefs: Prefs,
    /// Stable UI ids, parallel to `vault.entries` and `vault.logins`.
    pub code_ids: Vec<i32>,
    pub login_ids: Vec<i32>,
    pub next_id: i32,
    /// Indices into the vault lists of the rows currently shown.
    pub visible_codes: Vec<usize>,
    pub visible_logins: Vec<usize>,
    pub filter: String,
    pub code_rows: Rc<VecModel<CodeRow>>,
    pub login_rows: Rc<VecModel<LoginRow>>,
    pub export_codes: Rc<VecModel<PickRow>>,
    pub export_logins: Rc<VecModel<PickRow>>,
    /// Account ids behind the "2FA code" choices of the login editor (index 0 = none).
    pub otp_choice_ids: Vec<String>,
    pub failed_attempts: u32,
    pub locked_until: Option<Instant>,
    /// Exports are allowed without asking for the PIN again until then.
    pub confirmed_until: Option<Instant>,
    pub pending: Option<Pending>,
    pub pending_backup: Option<Vec<u8>>,
    /// Dialog to go back to when the QR code viewer closes.
    pub qr_return: Dialog,
    pub clipboard: Option<arboard::Clipboard>,
    pub copied: Option<Zeroizing<String>>,
    pub clipboard_timer: Timer,
    pub last_second: u64,
    pub last_activity: Instant,
    pub hwnd: isize,
    /// The notification-area icon is running.
    pub tray: bool,
    pub window_visible: bool,
    pub browser: browser::Browser,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static TOAST_TIMER: Timer = Timer::default();
}

pub fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow_mut().as_mut().expect("state not initialised")))
}

/// Like `with_state`, but silently skips if the state is busy (timers).
pub fn try_with_state(f: impl FnOnce(&mut State)) {
    STATE.with(|cell| {
        if let Ok(mut guard) = cell.try_borrow_mut()
            && let Some(state) = guard.as_mut()
        {
            f(state);
        }
    });
}

pub fn app(ui: &AppWindow) -> App<'_> {
    ui.global::<App>()
}

/// Records that the app was just used (postpones auto-lock).
pub fn touch() {
    try_with_state(|s| s.last_activity = Instant::now());
}

pub fn run(start_hidden: bool) -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let a = app(&ui);
    let vault_path = vault::default_path();
    let state = State {
        vault: None,
        prefs: Prefs::load(),
        code_ids: Vec::new(),
        login_ids: Vec::new(),
        next_id: 0,
        visible_codes: Vec::new(),
        visible_logins: Vec::new(),
        filter: String::new(),
        code_rows: Rc::new(VecModel::default()),
        login_rows: Rc::new(VecModel::default()),
        export_codes: Rc::new(VecModel::default()),
        export_logins: Rc::new(VecModel::default()),
        otp_choice_ids: Vec::new(),
        failed_attempts: 0,
        locked_until: None,
        confirmed_until: None,
        pending: None,
        pending_backup: None,
        qr_return: Dialog::None,
        clipboard: None,
        copied: None,
        clipboard_timer: Timer::default(),
        last_second: 0,
        last_activity: Instant::now(),
        hwnd: 0,
        tray: false,
        window_visible: false,
        browser: browser::Browser::default(),
        vault_path,
    };
    a.set_codes(ModelRc::from(state.code_rows.clone()));
    a.set_logins(ModelRc::from(state.login_rows.clone()));
    a.set_export_codes(ModelRc::from(state.export_codes.clone()));
    a.set_export_logins(ModelRc::from(state.export_logins.clone()));
    a.set_version(env!("CARGO_PKG_VERSION").into());
    a.set_data_path(state.vault_path.display().to_string().into());
    a.set_can_scan_screen(cfg!(windows));
    a.set_tray_supported(cfg!(windows));
    a.set_browser_enabled(state.prefs.browser_enabled);
    a.set_page(if vault::exists(&state.vault_path) { Page::Lock } else { Page::Setup });
    STATE.with(|cell| *cell.borrow_mut() = Some(state));

    session::wire(&ui);
    codes::wire(&ui);
    logins::wire(&ui);
    transfer::wire(&ui);
    window::wire(&ui);
    browser::wire(&ui);

    platform::refresh_autostart();
    browser::start(&ui);
    let tray = window::start_tray(&ui);
    let has_vault = with_state(|s| {
        s.tray = tray;
        vault::exists(&s.vault_path)
    });

    let ticker = Timer::default();
    let weak = ui.as_weak();
    ticker.start(TimerMode::Repeated, Duration::from_millis(250), move || {
        if let Some(ui) = weak.upgrade() {
            tick(&ui);
        }
    });

    // Started with Windows: stay in the notification area until needed.
    if !(start_hidden && tray && has_vault) {
        window::show(&ui);
    }
    slint::run_event_loop_until_quit()?;

    try_with_state(|s| {
        clear_clipboard_if_ours(s);
        s.vault = None;
    });
    Ok(())
}

fn tick(ui: &AppWindow) {
    browser::expire(ui);
    try_with_state(|s| {
        if s.hwnd == 0 {
            s.hwnd = native_handle(ui);
            if s.hwnd != 0 {
                let hide = s.vault.as_ref().map(|v| v.settings.hide_from_capture).unwrap_or(true);
                platform::set_capture_protection(s.hwnd, hide);
            }
        }
        let Some(vault) = s.vault.as_ref() else {
            return;
        };
        // Typing or clicking while our window is in front counts as using the app.
        if platform::is_foreground(s.hwnd) && platform::idle_seconds().is_some_and(|idle| idle < 2) {
            s.last_activity = Instant::now();
        }
        let minutes = vault.settings.auto_lock_minutes;
        if minutes > 0 && !app(ui).get_busy() && s.last_activity.elapsed() >= Duration::from_secs(minutes as u64 * 60) {
            session::lock_now(ui, s);
            return;
        }
        let now = otp::now_unix();
        if now != s.last_second {
            s.last_second = now;
            codes::update_rows(s, now);
            logins::update_rows(s, now);
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

// ------------------------------------------------------------------ messages

pub fn set_busy(ui: &AppWindow, text: &str) {
    let a = app(ui);
    a.set_busy_text(text.into());
    a.set_busy(true);
}

pub fn toast(ui: &AppWindow, error: bool, text: impl Into<String>) {
    let text = text.into();
    let a = app(ui);
    // Longer messages stay longer.
    let millis = (2200 + 45 * text.chars().count() as u64).min(9000);
    a.set_toast_text(text.into());
    a.set_toast_error(error);
    a.set_toast_visible(true);
    let weak = ui.as_weak();
    TOAST_TIMER.with(|t| {
        t.start(TimerMode::SingleShot, Duration::from_millis(millis), move || {
            if let Some(ui) = weak.upgrade() {
                app(&ui).set_toast_visible(false);
            }
        })
    });
}

/// Shows a message inside the open dialog if it has room for one, otherwise as a toast.
pub fn report(ui: &AppWindow, error: bool, text: impl Into<String>) {
    let text = text.into();
    let a = app(ui);
    match a.get_dialog() {
        Dialog::AddCode
        | Dialog::EditLogin
        | Dialog::Export
        | Dialog::Qr
        | Dialog::Pin
        | Dialog::Restore
        | Dialog::Settings
        | Dialog::Browser => {
            if error {
                a.set_dialog_info("".into());
                a.set_dialog_error(text.into());
            } else {
                a.set_dialog_error("".into());
                a.set_dialog_info(text.into());
            }
        }
        _ => toast(ui, error, text),
    }
}

pub fn open_dialog(ui: &AppWindow, dialog: Dialog) {
    let a = app(ui);
    a.set_dialog_error("".into());
    a.set_dialog_info("".into());
    a.set_dialog(dialog);
}

/// Closes the open dialog and forgets whatever secret it was showing.
pub fn close_dialog(ui: &AppWindow) {
    let a = app(ui);
    let current = a.get_dialog();
    let back = with_state(|s| {
        s.pending = None;
        s.pending_backup = None;
        let back = if current == Dialog::Qr { std::mem::replace(&mut s.qr_return, Dialog::None) } else { Dialog::None };
        if matches!(current, Dialog::Export) || back == Dialog::None {
            s.export_codes.set_vec(Vec::new());
            s.export_logins.set_vec(Vec::new());
        }
        back
    });
    match current {
        Dialog::EditLogin => logins::clear_editor(ui),
        Dialog::Qr => a.set_qr_images(ModelRc::default()),
        Dialog::Generator => a.set_gen_result("".into()),
        _ => {}
    }
    a.set_confirm_delete(false);
    open_dialog(ui, back);
    if back == Dialog::None {
        ui.invoke_focus_list();
    }
}

pub fn plural(n: usize, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
}

pub fn save(ui: &AppWindow, s: &State) -> bool {
    match s.vault.as_ref().map(|v| v.save()) {
        Some(Err(e)) => {
            report(ui, true, format!("Could not save: {e}"));
            false
        }
        _ => true,
    }
}

pub fn save_prefs(ui: &AppWindow, s: &State) {
    if let Err(e) = s.prefs.save() {
        report(ui, true, format!("Could not save the settings: {e}"));
    }
}

/// Refreshes both lists and the counters, keeping the selection.
pub fn refresh_all(ui: &AppWindow, s: &mut State) {
    codes::refresh(ui, s, None);
    logins::refresh(ui, s, None);
}

pub fn first_letter(text: &str) -> slint::SharedString {
    text.trim().chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_else(|| "?".into()).into()
}

/// Index of the selected row in `model`, if the selection is valid, and its id.
pub fn selected_id<T: Clone + 'static>(model: &VecModel<T>, index: i32, id: impl Fn(&T) -> i32) -> Option<i32> {
    if index < 0 {
        return None;
    }
    model.row_data(index as usize).map(|row| id(&row))
}

// ------------------------------------------------------------------ clipboard

fn clipboard(s: &mut State) -> Result<&mut arboard::Clipboard, String> {
    if s.clipboard.is_none() {
        s.clipboard = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
    }
    Ok(s.clipboard.as_mut().expect("just created"))
}

pub fn clipboard_content(s: &mut State) -> Result<ClipboardContent, String> {
    let cb = clipboard(s)?;
    if let Ok(img) = cb.get_image() {
        return Ok(ClipboardContent::Image(img.width, img.height, img.bytes.into_owned()));
    }
    cb.get_text().map(ClipboardContent::Text).map_err(|e| e.to_string())
}

pub enum ClipboardContent {
    Image(usize, usize, Vec<u8>),
    Text(String),
}

fn set_clipboard_secret(s: &mut State, text: &str) -> Result<(), String> {
    let cb = clipboard(s)?;
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        // Keep secrets out of Windows clipboard history and cloud clipboard.
        cb.set().exclude_from_monitoring().text(text.to_string()).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        cb.set_text(text.to_string()).map_err(|e| e.to_string())
    }
}

pub fn clear_clipboard_if_ours(s: &mut State) {
    if let Some(copied) = s.copied.take()
        && let Ok(cb) = clipboard(s)
        && cb.get_text().map(|t| t == *copied).unwrap_or(false)
    {
        let _ = cb.clear();
    }
}

/// Copies a code, password or username; the clipboard is cleared later.
pub fn copy_secret(ui: &AppWindow, s: &mut State, text: Zeroizing<String>, what: &str) {
    if text.is_empty() {
        toast(ui, true, format!("There is no {} to copy.", what.to_lowercase()));
        return;
    }
    let seconds = s.vault.as_ref().map(|v| v.settings.clipboard_clear_seconds).unwrap_or(30);
    match set_clipboard_secret(s, &text) {
        Ok(()) => {
            s.copied = Some(text);
            if seconds > 0 {
                s.clipboard_timer.start(TimerMode::SingleShot, Duration::from_secs(seconds as u64), || {
                    try_with_state(clear_clipboard_if_ours)
                });
                toast(ui, false, format!("{what} copied. The clipboard clears in {seconds} s."));
            } else {
                toast(ui, false, format!("{what} copied."));
            }
        }
        Err(e) => toast(ui, true, format!("Could not copy: {e}")),
    }
}

// ------------------------------------------------------------------ file dialogs

#[cfg(windows)]
pub mod dialogs {
    use super::AppWindow;
    use slint::ComponentHandle;
    use std::path::PathBuf;

    fn base(ui: &AppWindow, title: &str) -> rfd::FileDialog {
        rfd::FileDialog::new().set_parent(&ui.window().window_handle()).set_title(title)
    }
    pub fn open_image(ui: &AppWindow) -> Option<PathBuf> {
        base(ui, "Open QR code image").add_filter("Images", &["png", "jpg", "jpeg", "bmp", "gif", "webp"]).pick_file()
    }
    pub fn open_backup(ui: &AppWindow) -> Option<PathBuf> {
        base(ui, "Open backup file")
            .add_filter("Authenticator backup", &["json"])
            .add_filter("All files", &["*"])
            .pick_file()
    }
    pub fn open_csv(ui: &AppWindow) -> Option<PathBuf> {
        base(ui, "Import passwords (CSV exported by a browser or password manager)")
            .add_filter("CSV file", &["csv"])
            .add_filter("All files", &["*"])
            .pick_file()
    }
    pub fn save_backup(ui: &AppWindow, name: &str) -> Option<PathBuf> {
        base(ui, "Save backup file").set_file_name(name).add_filter("Authenticator backup", &["json"]).save_file()
    }
}

/// Development fallback: paths come from environment variables.
#[cfg(not(windows))]
pub mod dialogs {
    use super::AppWindow;
    use std::path::PathBuf;

    pub fn open_image(_: &AppWindow) -> Option<PathBuf> {
        std::env::var_os("AUTH_DEV_IMAGE").map(PathBuf::from)
    }
    pub fn open_backup(_: &AppWindow) -> Option<PathBuf> {
        std::env::var_os("AUTH_DEV_BACKUP").map(PathBuf::from)
    }
    pub fn open_csv(_: &AppWindow) -> Option<PathBuf> {
        std::env::var_os("AUTH_DEV_CSV").map(PathBuf::from)
    }
    pub fn save_backup(_: &AppWindow, name: &str) -> Option<PathBuf> {
        Some(std::env::temp_dir().join(name))
    }
}
