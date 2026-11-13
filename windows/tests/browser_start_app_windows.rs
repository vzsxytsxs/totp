//! Windows-only: when the browser asks and the app is not running, the host
//! starts it (in the notification area) and passes the request on.
//!
//! Starts the real app with a temporary data folder; only runs when
//! AUTH_TEST_SYSTEM=1 (set in CI). Kept in its own test program so that no
//! stand-in pipe server from the other tests is running.
#![cfg(windows)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use authenticator::browser::{self, install};
use serde_json::{Value, json};

#[test]
fn host_starts_the_app() {
    if !std::env::var("AUTH_TEST_SYSTEM").is_ok_and(|v| v == "1") {
        eprintln!("skipped (set AUTH_TEST_SYSTEM=1)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("authenticator-start-test-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("appdata")).unwrap();
    let app = env!("CARGO_BIN_EXE_authenticator");
    let mut image = std::fs::read(app).unwrap();
    install::set_console_subsystem(&mut image).unwrap();
    let host = dir.join("authenticator-host.exe");
    std::fs::write(&host, image).unwrap();
    std::fs::write(dir.join("app-path.txt"), app).unwrap();

    let mut child = Command::new(&host)
        .arg(browser::extension_origin())
        .env("APPDATA", dir.join("appdata"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start host");
    let message = serde_json::to_vec(&json!({
        "type": "request", "client": "test-client", "nonce": "", "data": "", "wait": false
    }))
    .unwrap();
    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(&(message.len() as u32).to_le_bytes()).unwrap();
    stdin.write_all(&message).unwrap();
    stdin.flush().unwrap();

    // The answer comes from the app the host started: the integration is
    // off in a fresh data folder.
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        let mut len = [0u8; 4];
        let result = stdout.read_exact(&mut len).and_then(|_| {
            let mut data = vec![0u8; u32::from_le_bytes(len) as usize];
            stdout.read_exact(&mut data).map(|_| data)
        });
        let _ = sender.send(result);
    });
    let reply = receiver.recv_timeout(Duration::from_secs(40));

    drop(child.stdin.take());
    let _ = child.kill();
    let _ = child.wait();
    // Stop the app that was started (and its window).
    let _ = Command::new("taskkill").args(["/IM", "authenticator.exe", "/F"]).output();
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::remove_dir_all(&dir);

    let reply: Value = serde_json::from_slice(&reply.expect("no answer in time").expect("read")).unwrap();
    assert_eq!(reply, json!({ "type": "error", "error": "disabled" }));
}
