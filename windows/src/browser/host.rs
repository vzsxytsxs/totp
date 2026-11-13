//! Native messaging host: the browser starts this program (a console copy of
//! the app, see `install.rs`) for the extension and talks to it through
//! standard input/output. It only relays messages to the running app,
//! starting the app in the notification area if it is not running.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{ipc, plain_error};

/// Runs the host; `origin` is the extension the browser started us for.
pub fn run(origin: &str) -> i32 {
    if origin.trim_end_matches('/') != super::extension_origin().trim_end_matches('/') {
        return 1;
    }
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut relay = Relay { app: None };
    loop {
        let message = match ipc::read_frame(&mut stdin) {
            Ok(Some(message)) => message,
            _ => return 0,
        };
        let reply = relay.handle(&message);
        if ipc::write_frame(&mut stdout, &reply).is_err() || stdout.flush().is_err() {
            return 0;
        }
    }
}

struct Relay {
    app: Option<ipc::Stream>,
}

impl Relay {
    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        let kind = serde_json::from_slice::<serde_json::Value>(message)
            .ok()
            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string));
        if kind.as_deref() == Some("ping") {
            return serde_json::to_vec(&serde_json::json!({
                "type": "pong",
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": super::PROTOCOL_VERSION,
            }))
            .expect("serializable");
        }
        // The app may need to come to the front to ask for the PIN.
        allow_foreground();

        if let Some(app) = self.app.as_mut() {
            if ipc::write_frame(app, message).is_ok() {
                return self.reply();
            }
            self.app = None;
        }
        match connect_or_start() {
            Ok(mut app) => {
                if ipc::write_frame(&mut app, message).is_err() {
                    return plain_error("app-unavailable");
                }
                self.app = Some(app);
                self.reply()
            }
            Err(error) => plain_error(error),
        }
    }

    fn reply(&mut self) -> Vec<u8> {
        match self.app.as_mut().map(ipc::read_frame) {
            Some(Ok(Some(reply))) => reply,
            _ => {
                self.app = None;
                plain_error("app-closed")
            }
        }
    }
}

fn connect_or_start() -> Result<ipc::Stream, &'static str> {
    match ipc::connect() {
        Ok(app) => return Ok(app),
        Err(e) if ipc::is_not_running(&e) => {}
        Err(_) => return Err("app-unavailable"),
    }
    if !start_app() {
        return Err("app-not-found");
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        if let Ok(app) = ipc::connect() {
            return Ok(app);
        }
    }
    Err("app-not-running")
}

/// The installed app, as recorded next to this host by the app itself.
fn app_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    match std::fs::read_to_string(exe.with_file_name("app-path.txt")) {
        Ok(text) if !text.trim().is_empty() => Some(PathBuf::from(text.trim())),
        _ => Some(exe),
    }
}

#[cfg(windows)]
fn start_app() -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation};
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };

    let Some(app) = app_path().filter(|p| p.exists()) else { return false };
    // The app must not keep the browser's pipes open after we exit.
    // SAFETY: only changes flags of our own standard handles.
    unsafe {
        for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = GetStdHandle(which);
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // Leave the browser's job object if allowed, so the app keeps running
    // when the browser stops this host.
    for flags in [base | CREATE_BREAKAWAY_FROM_JOB, base] {
        let mut command = Command::new(&app);
        command.arg("--tray").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).creation_flags(flags);
        if let Some(dir) = app.parent() {
            command.current_dir(dir);
        }
        if command.spawn().is_ok() {
            return true;
        }
    }
    false
}

#[cfg(not(windows))]
fn start_app() -> bool {
    use std::process::{Command, Stdio};
    let Some(app) = app_path() else { return false };
    Command::new(app).arg("--tray").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().is_ok()
}

#[cfg(windows)]
fn allow_foreground() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow};
    // SAFETY: plain call.
    unsafe { AllowSetForegroundWindow(ASFW_ANY) };
}

#[cfg(not(windows))]
fn allow_foreground() {}
