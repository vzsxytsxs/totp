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

#[cfg(not(windows))]
pub use fallback::*;

#[cfg(windows)]
mod win {
    use super::Capture;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, LocalFree};
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    const ENTROPY: &[u8] = b"Authenticator vault v1";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
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
                CryptProtectData(&input, description.as_ptr(), &entropy, null(), null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
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

    /// Returns false (after focusing the running copy) if the app is already open.
    pub fn acquire_single_instance(window_title: &str) -> bool {
        let name = wide("Local\\Authenticator-single-instance-7f3c2a");
        // SAFETY: the mutex handle is intentionally leaked; it lives as long as the process.
        unsafe {
            let handle = CreateMutexW(null(), 0, name.as_ptr());
            if !handle.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
                let title = wide(window_title);
                let hwnd = FindWindowW(null(), title.as_ptr());
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                }
                return false;
            }
        }
        true
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
    pub fn acquire_single_instance(_window_title: &str) -> bool {
        true
    }
}

