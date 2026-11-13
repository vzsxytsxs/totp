//! Windows-only checks of the browser integration: the named pipe, the
//! native messaging host relaying to it, and installing/removing the host.
//!
//! They use the real pipe name, registry keys and folders of the current
//! user, so they only run when AUTH_TEST_SYSTEM=1 (set in CI), never by
//! accident on a PC where Authenticator is in use.
#![cfg(windows)]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use authenticator::browser::{self, install, ipc};
use serde_json::{Value, json};

fn enabled() -> bool {
    std::env::var("AUTH_TEST_SYSTEM").is_ok_and(|v| v == "1")
}

fn send(child: &mut Child, message: &Value) {
    let data = serde_json::to_vec(message).unwrap();
    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(&(data.len() as u32).to_le_bytes()).unwrap();
    stdin.write_all(&data).unwrap();
    stdin.flush().unwrap();
}

fn receive(child: &mut Child) -> Value {
    let stdout = child.stdout.as_mut().unwrap();
    let mut len = [0u8; 4];
    stdout.read_exact(&mut len).unwrap();
    let mut data = vec![0u8; u32::from_le_bytes(len) as usize];
    stdout.read_exact(&mut data).unwrap();
    serde_json::from_slice(&data).unwrap()
}

fn wait_exit(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    None
}

/// A console copy of the app, the way `install` prepares it for browsers.
fn host_copy(dir: &std::path::Path, app_path: Option<&str>) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let mut image = std::fs::read(env!("CARGO_BIN_EXE_authenticator")).unwrap();
    install::set_console_subsystem(&mut image).unwrap();
    let host = dir.join("authenticator-host.exe");
    std::fs::write(&host, image).unwrap();
    if let Some(app) = app_path {
        std::fs::write(dir.join("app-path.txt"), app).unwrap();
    }
    host
}

#[test]
fn pipe_and_host_relay() {
    if !enabled() {
        eprintln!("skipped (set AUTH_TEST_SYSTEM=1)");
        return;
    }
    // Stand-in for the app: answers every message with what it received.
    ipc::serve(|mut stream| {
        while let Ok(Some(message)) = ipc::read_frame(&mut stream) {
            let got: Value = serde_json::from_slice(&message).unwrap_or(Value::Null);
            let reply = serde_json::to_vec(&json!({ "type": "echo", "got": got })).unwrap();
            if ipc::write_frame(&mut stream, &reply).is_err() {
                return;
            }
        }
    })
    .expect("pipe server");
    // Only one owner of the pipe (a second copy of the app is refused).
    assert!(ipc::serve(|_| {}).is_err());

    // Direct connection, twice on the same pipe.
    let mut client = ipc::connect().expect("connect");
    for i in 0..2 {
        ipc::write_frame(&mut client, format!("{{\"n\":{i}}}").as_bytes()).unwrap();
        let reply: Value = serde_json::from_slice(&ipc::read_frame(&mut client).unwrap().unwrap()).unwrap();
        assert_eq!(reply["got"]["n"], i);
    }

    // The host, started the way a browser starts it.
    let dir = std::env::temp_dir().join(format!("authenticator-host-test-{}", std::process::id()));
    let host = host_copy(&dir, None);
    let mut child = Command::new(&host)
        .arg(browser::extension_origin())
        .arg("--parent-window=0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start host");
    send(&mut child, &json!({ "type": "ping" }));
    let pong = receive(&mut child);
    assert_eq!(pong["type"], "pong");
    assert_eq!(pong["version"], env!("CARGO_PKG_VERSION"));
    for i in 0..3 {
        send(&mut child, &json!({ "type": "request", "client": "test-client", "n": i }));
        let reply = receive(&mut child);
        assert_eq!(reply["type"], "echo", "{reply}");
        assert_eq!(reply["got"]["n"], i);
    }
    // Closing its input (the browser disconnecting) ends the host.
    drop(child.stdin.take());
    assert_eq!(wait_exit(&mut child, Duration::from_secs(10)), Some(0));

    // Started for another extension: refuses to run.
    let mut other = Command::new(&host)
        .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(wait_exit(&mut other, Duration::from_secs(10)), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn install_and_remove_for_browsers() {
    if !enabled() {
        eprintln!("skipped (set AUTH_TEST_SYSTEM=1)");
        return;
    }
    let paths = install::install().expect("install");
    assert!(paths.extension.join("manifest.json").exists());
    assert!(paths.extension.join("icons").join("128.png").exists());
    assert!(paths.host.exists());
    let manifest: Value = serde_json::from_slice(&std::fs::read(&paths.manifest).unwrap()).unwrap();
    assert_eq!(manifest["path"].as_str().map(std::path::PathBuf::from), Some(paths.host.clone()));
    let key = format!(r"Software\Google\Chrome\NativeMessagingHosts\{}", browser::HOST_NAME);
    assert_eq!(authenticator::platform::reg_get(&key, None), Some(paths.manifest.to_string_lossy().into_owned()));
    let thorium = format!(r"Software\Thorium\NativeMessagingHosts\{}", browser::HOST_NAME);
    assert!(authenticator::platform::reg_get(&thorium, None).is_some());
    // Installing again (every start of the app) is fine.
    install::install().expect("install again");

    install::uninstall();
    assert_eq!(authenticator::platform::reg_get(&key, None), None);
    assert!(!paths.host.exists());
    assert!(!paths.manifest.exists());
    // The extension stays, so a browser that loaded it does not complain.
    assert!(paths.extension.join("manifest.json").exists());
}
