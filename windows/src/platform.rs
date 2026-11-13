//! OS integration. Real implementations are for Windows; the fallbacks only
//! exist so the app can be built and tested on other systems.

/// Captured screen in RGBA.
pub struct Capture {
    pub width: usize,
    pub height: usize,
    pub rgba: Vec<u8>,
}

#[cfg(windows)]
pub use win::*;

/// Calendar date (UTC) of a unix time, "2025-03-31".
pub fn utc_date(unix: i64) -> String {
    // Days since the epoch to a civil date (H. Hinnant's algorithm).
    let z = unix.div_euclid(86_400) + 719_468;
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

#[cfg(not(windows))]
pub use fallback::*;

#[cfg(windows)]
mod win {
    use super::Capture;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_SUCCESS, FILETIME, GetLastError, HWND, LocalFree, SYSTEMTIME,
    };
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW, RegSetKeyValueW,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    const ENTROPY: &[u8] = b"Authenticator vault v1";

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_os(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn data_dir() -> PathBuf {
        let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        base.join("Authenticator")
    }

    fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        let description = wide("Authenticator");
        // SAFETY: all pointers are valid for the duration of the call; the
        // output buffer is allocated by Windows and released with LocalFree.
        let ok = unsafe {
            if protect {
                CryptProtectData(
                    &input,
                    description.as_ptr(),
                    &entropy,
                    null(),
                    null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            } else {
                CryptUnprotectData(&input, null_mut(), &entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if ok == 0 || output.pbData.is_null() {
            return Err(if protect {
                "Windows refused to encrypt the data (DPAPI)".into()
            } else {
                "This file belongs to another Windows user or computer".into()
            });
        }
        // SAFETY: Windows returned a buffer of cbData bytes.
        let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            LocalFree(output.pbData as _);
        }
        Ok(result)
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        dpapi(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        dpapi(data, false)
    }

    /// Captures all monitors (the whole virtual desktop).
    pub fn capture_screen() -> Option<Capture> {
        // SAFETY: plain GDI calls; every handle created here is released below.
        unsafe {
            let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            let h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
            if w <= 0 || h <= 0 {
                return None;
            }
            let screen = GetDC(null_mut());
            if screen.is_null() {
                return None;
            }
            let mem = CreateCompatibleDC(screen);
            let bitmap = CreateCompatibleBitmap(screen, w, h);
            let old = SelectObject(mem, bitmap as _);
            let copied = BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY | CAPTUREBLT) != 0;
            let mut info: BITMAPINFO = std::mem::zeroed();
            info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            info.bmiHeader.biWidth = w;
            info.bmiHeader.biHeight = -h; // top-down rows
            info.bmiHeader.biPlanes = 1;
            info.bmiHeader.biBitCount = 32;
            info.bmiHeader.biCompression = BI_RGB;
            let mut pixels = vec![0u8; w as usize * h as usize * 4];
            let lines = if copied {
                GetDIBits(mem, bitmap, 0, h as u32, pixels.as_mut_ptr() as _, &mut info, DIB_RGB_COLORS)
            } else {
                0
            };
            SelectObject(mem, old);
            DeleteObject(bitmap as _);
            DeleteDC(mem);
            ReleaseDC(null_mut(), screen);
            if lines == 0 {
                return None;
            }
            for px in pixels.chunks_exact_mut(4) {
                px.swap(0, 2); // BGRA -> RGBA
                px[3] = 255;
            }
            Some(Capture { width: w as usize, height: h as usize, rgba: pixels })
        }
    }

    /// Hides the window from screenshots, screen recording and screen sharing.
    pub fn set_capture_protection(hwnd: isize, enabled: bool) {
        if hwnd == 0 {
            return;
        }
        // SAFETY: hwnd is our own top-level window.
        unsafe {
            let hwnd = hwnd as HWND;
            if enabled {
                if SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) == 0 {
                    // Windows older than 10 2004: show the window black instead.
                    SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
                }
            } else {
                SetWindowDisplayAffinity(hwnd, WDA_NONE);
            }
        }
    }

    /// Seconds since the last keyboard/mouse input anywhere in the session.
    pub fn idle_seconds() -> Option<u64> {
        let mut info = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        // SAFETY: info is a properly initialised LASTINPUTINFO.
        unsafe {
            if GetLastInputInfo(&mut info) == 0 {
                return None;
            }
            Some((GetTickCount().wrapping_sub(info.dwTime) / 1000) as u64)
        }
    }

    /// Opens a web address in the default browser, or a folder in Explorer.
    pub fn open_external(target: &std::ffi::OsStr) -> bool {
        let target = wide_os(target);
        let verb = wide("open");
        // SAFETY: valid NUL-terminated strings; ShellExecuteW returns a value > 32 on success.
        unsafe {
            ShellExecuteW(null_mut(), verb.as_ptr(), target.as_ptr(), null(), null(), SW_SHOWNORMAL) as isize > 32
        }
    }

    pub fn is_foreground(hwnd: isize) -> bool {
        // SAFETY: no arguments.
        hwnd != 0 && unsafe { GetForegroundWindow() } as isize == hwnd
    }

    /// Local calendar date of a unix time ("2025-03-31").
    pub fn local_date(unix: i64) -> String {
        let ticks = (unix.max(0) as u64 + 11_644_473_600) * 10_000_000;
        let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
        // SAFETY: plain conversions between initialised structs.
        unsafe {
            let mut utc: SYSTEMTIME = std::mem::zeroed();
            let mut local: SYSTEMTIME = std::mem::zeroed();
            if FileTimeToSystemTime(&ft, &mut utc) != 0
                && SystemTimeToTzSpecificLocalTime(null(), &utc, &mut local) != 0
            {
                return format!("{:04}-{:02}-{:02}", local.wYear, local.wMonth, local.wDay);
            }
        }
        super::utc_date(unix)
    }

    // ---- registry (HKEY_CURRENT_USER only)

    pub fn reg_get(subkey: &str, name: Option<&str>) -> Option<String> {
        let subkey = wide(subkey);
        let name = name.map(wide);
        let name_ptr = name.as_ref().map(|n| n.as_ptr()).unwrap_or(null());
        let mut buf = vec![0u16; 2048];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: buffer and length describe valid writable memory.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name_ptr,
                RRF_RT_REG_SZ,
                null_mut(),
                buf.as_mut_ptr() as _,
                &mut len,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let chars = (len as usize / 2).min(buf.len());
        let text = String::from_utf16_lossy(&buf[..chars]);
        Some(text.trim_end_matches('\0').to_string())
    }

    /// Writes a string value, creating the key if needed. `None` is the key's default value.
    pub fn reg_set(subkey: &str, name: Option<&str>, value: &str) -> Result<(), String> {
        let subkey = wide(subkey);
        let name = name.map(wide);
        let name_ptr = name.as_ref().map(|n| n.as_ptr()).unwrap_or(null());
        let data = wide(value);
        // SAFETY: valid strings; the data length includes the terminating NUL.
        let status = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                name_ptr,
                REG_SZ,
                data.as_ptr() as _,
                (data.len() * 2) as u32,
            )
        };
        if status == ERROR_SUCCESS { Ok(()) } else { Err(format!("registry error {status}")) }
    }

    pub fn reg_delete_value(subkey: &str, name: &str) {
        let subkey = wide(subkey);
        let name = wide(name);
        // SAFETY: valid strings.
        unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey.as_ptr(), name.as_ptr()) };
    }

    pub fn reg_delete_key(subkey: &str) {
        let subkey = wide(subkey);
        // SAFETY: valid string; deletes only below HKEY_CURRENT_USER\subkey.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr()) };
    }

    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const RUN_VALUE: &str = "Authenticator";

    fn autostart_command() -> Option<String> {
        let exe = std::env::current_exe().ok()?;
        Some(format!("\"{}\" --tray", exe.display()))
    }

    pub fn autostart_enabled() -> bool {
        reg_get(RUN_KEY, Some(RUN_VALUE)).is_some()
    }

    pub fn set_autostart(enabled: bool) -> Result<(), String> {
        if enabled {
            let command = autostart_command().ok_or("Could not find the program file")?;
            reg_set(RUN_KEY, Some(RUN_VALUE), &command)
        } else {
            reg_delete_value(RUN_KEY, RUN_VALUE);
            Ok(())
        }
    }

    /// Keeps the start-with-Windows entry pointing at this copy of the program
    /// (in case the .exe was moved or updated to a new folder).
    pub fn refresh_autostart() {
        if let (Some(current), Some(wanted)) = (reg_get(RUN_KEY, Some(RUN_VALUE)), autostart_command()) {
            if current != wanted {
                let _ = reg_set(RUN_KEY, Some(RUN_VALUE), &wanted);
            }
        }
    }

    /// Returns false if the app is already running; with `show_existing`,
    /// the running copy is asked to show its window.
    pub fn acquire_single_instance(window_title: &str, show_existing: bool) -> bool {
        let name = wide("Local\\Authenticator-single-instance-7f3c2a");
        // SAFETY: the mutex handle is intentionally leaked; it lives as long as the process.
        unsafe {
            let handle = CreateMutexW(null(), 0, name.as_ptr());
            if !handle.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
                if show_existing && !crate::tray::signal_running_instance() {
                    // Older copy without a tray window: focus its window directly.
                    let title = wide(window_title);
                    let hwnd = FindWindowW(null(), title.as_ptr());
                    if !hwnd.is_null() {
                        ShowWindow(hwnd, SW_RESTORE);
                        SetForegroundWindow(hwnd);
                    }
                }
                return false;
            }
        }
        true
    }

    /// Brings our window in front of the others.
    pub fn bring_to_front(hwnd: isize) {
        if hwnd == 0 {
            return;
        }
        // SAFETY: hwnd is our own top-level window.
        unsafe {
            let hwnd = hwnd as HWND;
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(not(windows))]
mod fallback {
    use super::Capture;
    use std::path::PathBuf;

    pub fn data_dir() -> PathBuf {
        if let Some(dir) = std::env::var_os("AUTHENTICATOR_DATA_DIR") {
            return PathBuf::from(dir);
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("authenticator")
    }
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
    pub fn capture_screen() -> Option<Capture> {
        None
    }
    pub fn set_capture_protection(_hwnd: isize, _enabled: bool) {}
    pub fn idle_seconds() -> Option<u64> {
        None
    }
    pub fn acquire_single_instance(_window_title: &str, _show_existing: bool) -> bool {
        true
    }
    pub fn bring_to_front(_hwnd: isize) {}
    pub fn open_external(target: &std::ffi::OsStr) -> bool {
        std::process::Command::new("xdg-open").arg(target).spawn().is_ok()
    }
    pub fn is_foreground(_hwnd: isize) -> bool {
        false
    }
    pub fn local_date(unix: i64) -> String {
        super::utc_date(unix)
    }
    pub fn autostart_enabled() -> bool {
        false
    }
    pub fn set_autostart(_enabled: bool) -> Result<(), String> {
        Err("Only available on Windows".into())
    }
    pub fn refresh_autostart() {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_dates() {
        assert_eq!(super::utc_date(0), "1970-01-01");
        assert_eq!(super::utc_date(1_700_000_000), "2023-11-14");
        assert_eq!(super::utc_date(951_782_400), "2000-02-29");
    }
}
