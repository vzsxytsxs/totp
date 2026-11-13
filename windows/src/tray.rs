//! Notification-area (system tray) icon, plus the Windows events that should
//! lock the app (Win+L, switching user, sleep).
//!
//! The icon lives on its own thread with a hidden window and message loop, so
//! it keeps working while the main window is hidden. Events are handed to a
//! callback, which forwards them to the UI thread.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayEvent {
    /// Left click on the icon, "Open" in its menu, or the app was started again.
    Open,
    Lock,
    Quit,
    /// Windows locked (Win+L) or the user switched away.
    SessionLocked,
    /// The PC is going to sleep or hibernate.
    Suspend,
}

#[cfg(windows)]
pub use win::*;

#[cfg(not(windows))]
mod fallback {
    use super::TrayEvent;

    /// No tray outside Windows: returns false.
    pub fn start(_on_event: impl Fn(TrayEvent) + Send + Sync + 'static) -> bool {
        false
    }
    pub fn set_locked(_locked: bool) {}
    pub fn notify(_title: &str, _text: &str) {}
    pub fn stop() {}
    pub fn signal_running_instance() -> bool {
        false
    }
}

#[cfg(not(windows))]
pub use fallback::*;

#[cfg(windows)]
mod win {
    use super::TrayEvent;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
    use std::sync::{Mutex, OnceLock, mpsc};

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification};
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NIM_SETVERSION, NIN_SELECT, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    use crate::platform::wide;

    const CLASS_NAME: &str = "AuthenticatorTrayWindow-7f3c2a";
    const WM_TRAY: u32 = WM_APP + 1;
    const WM_SHOW_REQUEST: u32 = WM_APP + 2;
    const WM_UPDATE: u32 = WM_APP + 3;
    const WM_NOTIFY_BALLOON: u32 = WM_APP + 4;
    const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
    const WM_WTSSESSION_CHANGE_: u32 = 0x02B1;
    const WTS_CONSOLE_DISCONNECT: usize = 2;
    const WTS_REMOTE_DISCONNECT: usize = 4;
    const WTS_SESSION_LOCK: usize = 7;
    const WM_POWERBROADCAST_: u32 = 0x0218;
    const PBT_APMSUSPEND: usize = 4;

    const CMD_OPEN: usize = 1;
    const CMD_LOCK: usize = 2;
    const CMD_QUIT: usize = 3;

    static HANDLER: OnceLock<Box<dyn Fn(TrayEvent) + Send + Sync>> = OnceLock::new();
    static WINDOW: AtomicIsize = AtomicIsize::new(0);
    static LOCKED: AtomicBool = AtomicBool::new(true);
    static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
    static BALLOON: Mutex<Option<(String, String)>> = Mutex::new(None);

    fn emit(event: TrayEvent) {
        if let Some(handler) = HANDLER.get() {
            handler(event);
        }
    }

    fn copy_into(dst: &mut [u16], text: &str) {
        let units: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
        dst[..units.len()].copy_from_slice(&units);
        dst[units.len()] = 0;
    }

    fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
        // SAFETY: NOTIFYICONDATAW is plain data; all-zero is a valid starting point.
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = hwnd;
        data.uID = 1;
        data
    }

    fn tooltip() -> &'static str {
        if LOCKED.load(Ordering::Relaxed) { "Authenticator (locked)" } else { "Authenticator (unlocked)" }
    }

    unsafe fn add_icon(hwnd: HWND) {
        // SAFETY (whole function): plain Win32 calls with valid, initialised arguments.
        unsafe {
            let instance = GetModuleHandleW(null());
            let size_x = GetSystemMetrics(SM_CXSMICON);
            let size_y = GetSystemMetrics(SM_CYSMICON);
            // Resource 1 is the program icon embedded by build.rs.
            let mut icon = LoadImageW(instance, 1usize as *const u16, IMAGE_ICON, size_x, size_y, LR_DEFAULTCOLOR);
            if icon.is_null() {
                icon = LoadIconW(null_mut(), IDI_APPLICATION) as _;
            }
            let mut data = icon_data(hwnd);
            data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
            data.uCallbackMessage = WM_TRAY;
            data.hIcon = icon as _;
            copy_into(&mut data.szTip, tooltip());
            Shell_NotifyIconW(NIM_ADD, &data);
            data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &data);
        }
    }

    unsafe fn show_menu(hwnd: HWND) {
        // SAFETY (whole function): the menu is created, shown and destroyed here.
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            let open = wide("Open Authenticator");
            let lock = wide("Lock");
            let quit = wide("Quit");
            AppendMenuW(menu, MF_STRING, CMD_OPEN, open.as_ptr());
            let lock_flags = if LOCKED.load(Ordering::Relaxed) { MF_STRING | MF_GRAYED } else { MF_STRING };
            AppendMenuW(menu, lock_flags, CMD_LOCK, lock.as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, CMD_QUIT, quit.as_ptr());
            SetMenuDefaultItem(menu, CMD_OPEN as u32, 0);
            let mut point = POINT { x: 0, y: 0 };
            GetCursorPos(&mut point);
            // Needed so the menu closes when clicking elsewhere.
            SetForegroundWindow(hwnd);
            let command = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                point.x,
                point.y,
                0,
                hwnd,
                null(),
            );
            PostMessageW(hwnd, WM_NULL, 0, 0);
            DestroyMenu(menu);
            match command as usize {
                CMD_OPEN => emit(TrayEvent::Open),
                CMD_LOCK => emit(TrayEvent::Lock),
                CMD_QUIT => emit(TrayEvent::Quit),
                _ => {}
            }
        }
    }

    unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // SAFETY (whole function): called by Windows for our own window.
        unsafe {
            match message {
                WM_TRAY => {
                    match (lparam as u32) & 0xFFFF {
                        NIN_SELECT | NIN_KEYSELECT => emit(TrayEvent::Open),
                        WM_CONTEXTMENU => show_menu(hwnd),
                        _ => {}
                    }
                    0
                }
                WM_SHOW_REQUEST => {
                    emit(TrayEvent::Open);
                    0
                }
                WM_UPDATE => {
                    let mut data = icon_data(hwnd);
                    data.uFlags = NIF_TIP | NIF_SHOWTIP;
                    copy_into(&mut data.szTip, tooltip());
                    Shell_NotifyIconW(NIM_MODIFY, &data);
                    0
                }
                WM_NOTIFY_BALLOON => {
                    if let Some((title, text)) = BALLOON.lock().ok().and_then(|mut b| b.take()) {
                        let mut data = icon_data(hwnd);
                        data.uFlags = NIF_INFO;
                        data.dwInfoFlags = NIIF_INFO;
                        copy_into(&mut data.szInfoTitle, &title);
                        copy_into(&mut data.szInfo, &text);
                        Shell_NotifyIconW(NIM_MODIFY, &data);
                    }
                    0
                }
                WM_WTSSESSION_CHANGE_ => {
                    if matches!(wparam, WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) {
                        emit(TrayEvent::SessionLocked);
                    }
                    0
                }
                WM_POWERBROADCAST_ => {
                    if wparam == PBT_APMSUSPEND {
                        emit(TrayEvent::Suspend);
                    }
                    1
                }
                WM_CLOSE => {
                    Shell_NotifyIconW(NIM_DELETE, &icon_data(hwnd));
                    DestroyWindow(hwnd);
                    0
                }
                WM_DESTROY => {
                    WINDOW.store(0, Ordering::Relaxed);
                    PostQuitMessage(0);
                    0
                }
                _ if message != 0 && message == TASKBAR_CREATED.load(Ordering::Relaxed) => {
                    // Explorer restarted: the icon has to be added again.
                    add_icon(hwnd);
                    0
                }
                _ => DefWindowProcW(hwnd, message, wparam, lparam),
            }
        }
    }

    /// Shows the icon. `on_event` is called on the tray thread.
    pub fn start(on_event: impl Fn(TrayEvent) + Send + Sync + 'static) -> bool {
        if HANDLER.set(Box::new(on_event)).is_err() {
            return false;
        }
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("tray".into())
            .spawn(move || {
                // SAFETY: standard window class registration, window creation and message loop.
                unsafe {
                    let instance = GetModuleHandleW(null());
                    let class_name = wide(CLASS_NAME);
                    let class = WNDCLASSEXW {
                        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                        style: 0,
                        lpfnWndProc: Some(window_proc),
                        cbClsExtra: 0,
                        cbWndExtra: 0,
                        hInstance: instance,
                        hIcon: null_mut(),
                        hCursor: null_mut(),
                        hbrBackground: null_mut(),
                        lpszMenuName: null(),
                        lpszClassName: class_name.as_ptr(),
                        hIconSm: null_mut(),
                    };
                    RegisterClassExW(&class);
                    let taskbar = wide("TaskbarCreated");
                    TASKBAR_CREATED.store(RegisterWindowMessageW(taskbar.as_ptr()), Ordering::Relaxed);
                    // A real (never shown) top-level window: message-only windows
                    // do not receive the sleep and session broadcasts.
                    let title = wide("Authenticator tray");
                    let hwnd = CreateWindowExW(
                        WS_EX_TOOLWINDOW,
                        class_name.as_ptr(),
                        title.as_ptr(),
                        WS_OVERLAPPED,
                        0,
                        0,
                        0,
                        0,
                        null_mut(),
                        null_mut(),
                        instance,
                        null(),
                    );
                    if hwnd.is_null() {
                        let _ = ready_tx.send(false);
                        return;
                    }
                    WINDOW.store(hwnd as isize, Ordering::Relaxed);
                    WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
                    add_icon(hwnd);
                    let _ = ready_tx.send(true);
                    let mut message: MSG = std::mem::zeroed();
                    while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
                        TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
            })
            .is_ok()
            && ready_rx.recv().unwrap_or(false)
    }

    fn post(message: u32) {
        let hwnd = WINDOW.load(Ordering::Relaxed);
        if hwnd != 0 {
            // SAFETY: posting to our own window; it may already be gone, which is harmless.
            unsafe { PostMessageW(hwnd as HWND, message, 0, 0) };
        }
    }

    /// Updates the tooltip and whether "Lock" is available.
    pub fn set_locked(locked: bool) {
        LOCKED.store(locked, Ordering::Relaxed);
        post(WM_UPDATE);
    }

    /// Shows a notification balloon next to the icon.
    pub fn notify(title: &str, text: &str) {
        if let Ok(mut balloon) = BALLOON.lock() {
            *balloon = Some((title.to_string(), text.to_string()));
        }
        post(WM_NOTIFY_BALLOON);
    }

    /// Removes the icon (when quitting).
    pub fn stop() {
        let hwnd = WINDOW.load(Ordering::Relaxed);
        if hwnd != 0 {
            // SAFETY: synchronous call to our own window, which removes the icon and closes.
            unsafe { SendMessageW(hwnd as HWND, WM_CLOSE, 0, 0) };
        }
    }

    /// Asks an already running copy of the app to show its window.
    pub fn signal_running_instance() -> bool {
        let class_name = wide(CLASS_NAME);
        // SAFETY: plain lookups and a posted message.
        unsafe {
            let hwnd = FindWindowW(class_name.as_ptr(), null());
            if hwnd.is_null() {
                return false;
            }
            // We were just started by the user, so we may hand over the right
            // to bring a window to the front.
            AllowSetForegroundWindow(ASFW_ANY);
            PostMessageW(hwnd, WM_SHOW_REQUEST, 0, 0) != 0
        }
    }
}
