//! Local channel between the native messaging host and the app.
//!
//! Windows: a named pipe that only the current Windows user (and SYSTEM) may
//! open, refusing remote clients. Elsewhere (development builds): a Unix
//! socket in the data folder.
//!
//! Messages are framed as a 4-byte little-endian length followed by JSON,
//! the same framing browsers use for native messaging.

use std::io::{self, Read, Write};

/// Larger messages are refused (browsers allow at most 1 MB towards the extension).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Reads one frame; `Ok(None)` when the other side closed the connection.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match reader.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    Ok(Some(data))
}

pub fn write_frame(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&(data.len() as u32).to_le_bytes());
    frame.extend_from_slice(data);
    writer.write_all(&frame)?;
    writer.flush()
}

/// True when connecting failed because the app is not running.
pub fn is_not_running(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused)
}

#[cfg(windows)]
pub use win::{Stream, connect, serve};

#[cfg(not(windows))]
pub use unix::{Stream, connect, serve};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::platform::wide;

    pub type Stream = File;

    /// "S-1-5-21-…" of the current user.
    fn user_sid() -> io::Result<String> {
        // SAFETY: plain Win32 calls; the buffer is sized by the first call and
        // u64-aligned for TOKEN_USER; the returned string is freed with LocalFree.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buffer = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len);
            let error = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(error);
            }
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut text: *mut u16 = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut end = 0;
            while *text.add(end) != 0 {
                end += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, end));
            LocalFree(text.cast());
            Ok(sid)
        }
    }

    fn pipe_name() -> io::Result<String> {
        Ok(format!(r"\\.\pipe\{}-{}", super::super::HOST_NAME, user_sid()?))
    }

    struct Security {
        descriptor: *mut c_void,
    }

    impl Security {
        /// Full access for the current user and SYSTEM only.
        fn for_user(sid: &str) -> io::Result<Security> {
            let sddl = wide(&format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)"));
            let mut descriptor = null_mut();
            // SAFETY: valid NUL-terminated SDDL; the descriptor is freed in Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Security { descriptor })
        }
    }

    // SAFETY: the descriptor is a private heap allocation, only read by the
    // thread that owns it.
    unsafe impl Send for Security {}

    impl Drop for Security {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.descriptor) };
        }
    }

    fn create_instance(name: &[u16], security: &Security, first: bool) -> io::Result<File> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.descriptor,
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        // SAFETY: valid name and security attributes for the duration of the call.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: we own the new handle; File closes it.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn wait_for_client(pipe: &File) -> io::Result<()> {
        // SAFETY: synchronous (non-overlapped) pipe handle.
        if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), null_mut()) } != 0 {
            return Ok(());
        }
        // SAFETY: plain call.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Starts accepting connections on a background thread; `handler` runs
    /// on its own thread for each connection. Fails if another copy of the
    /// app (or anything else) already owns the pipe.
    pub fn serve(handler: impl Fn(Stream) + Send + Sync + 'static) -> io::Result<()> {
        let sid = user_sid()?;
        let name = wide(&pipe_name()?);
        let security = Security::for_user(&sid)?;
        let mut pipe = create_instance(&name, &security, true)?;
        std::thread::Builder::new().name("browser-pipe".into()).spawn(move || {
            let handler = std::sync::Arc::new(handler);
            loop {
                if wait_for_client(&pipe).is_err() {
                    std::thread::sleep(Duration::from_millis(200));
                    if let Ok(fresh) = create_instance(&name, &security, false) {
                        pipe = fresh;
                    }
                    continue;
                }
                let next = loop {
                    match create_instance(&name, &security, false) {
                        Ok(next) => break next,
                        Err(_) => std::thread::sleep(Duration::from_millis(500)),
                    }
                };
                let client = std::mem::replace(&mut pipe, next);
                let handler = handler.clone();
                let _ = std::thread::Builder::new().name("browser-client".into()).spawn(move || handler(client));
            }
        })?;
        Ok(())
    }

    /// Connects to the running app. Fails with `NotFound` when it is not running.
    pub fn connect() -> io::Result<Stream> {
        let name = pipe_name()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
                .open(&name)
            {
                Ok(file) => return Ok(file),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(not(windows))]
mod unix {
    use std::io;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;

    pub type Stream = UnixStream;

    fn socket_path() -> PathBuf {
        crate::platform::data_dir().join("browser.sock")
    }

    pub fn serve(handler: impl Fn(Stream) + Send + Sync + 'static) -> io::Result<()> {
        let path = socket_path();
        if UnixStream::connect(&path).is_ok() {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "another copy is running"));
        }
        let _ = std::fs::remove_file(&path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let listener = UnixListener::bind(&path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::thread::Builder::new().name("browser-socket".into()).spawn(move || {
            let handler = std::sync::Arc::new(handler);
            for client in listener.incoming().flatten() {
                let handler = handler.clone();
                let _ = std::thread::Builder::new().name("browser-client".into()).spawn(move || handler(client));
            }
        })?;
        Ok(())
    }

    pub fn connect() -> io::Result<Stream> {
        UnixStream::connect(socket_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"{\"a\":1}").unwrap();
        write_frame(&mut buffer, b"").unwrap();
        assert_eq!(&buffer[..4], &7u32.to_le_bytes());
        let mut reader = &buffer[..];
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"");
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let mut big = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        big.extend_from_slice(b"xx");
        assert!(read_frame(&mut &big[..]).is_err());
        let mut short = 10u32.to_le_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(read_frame(&mut &short[..]).is_err());
        assert!(read_frame(&mut &[1u8, 0][..]).is_err());
    }
}
