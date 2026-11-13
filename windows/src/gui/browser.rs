//! Answers the browser extension (protocol in `authenticator::browser` and
//! `docs/browser-protocol.md`).
//!
//! Requests arrive on background threads (one per connection) and are handed
//! to the UI thread; the connection thread waits for the answer. While the
//! app is locked, a request that asks to wait brings the window up for the
//! PIN and is answered after unlocking.

use std::collections::VecDeque;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::{Duration, Instant};

use authenticator::browser::{
    self, Direction, Envelope, LoginSummary, ReplayGuard, Request, install, ipc, plain_error,
};
use authenticator::crypto;
use authenticator::login::{Login, Site, match_score};
use authenticator::otp::{self, OtpKind};
use authenticator::vault::BrowserClient;
use serde_json::{Value, json};
use slint::{ComponentHandle, ModelRc, VecModel};
use zeroize::Zeroizing;

use super::*;

/// How long a request may wait for the PIN or an answer in the app.
const WAIT_LIMIT: Duration = Duration::from_secs(150);
/// Requests waiting for the PIN at the same time.
const MAX_WAITING: usize = 8;
/// Logins returned for one page at most.
const MAX_LOGINS: usize = 50;

/// Answer channel back to the connection thread. Dropping it unanswered
/// makes the thread reply "cancelled".
pub struct Reply(SyncSender<Vec<u8>>);

impl Reply {
    fn send(self, data: Vec<u8>) {
        let _ = self.0.send(data);
    }
    fn error(self, error: &str) {
        self.send(plain_error(error));
    }
}

struct Waiting {
    envelope: Envelope,
    reply: Reply,
    deadline: Instant,
}

struct PairRequest {
    client: String,
    name: String,
    key: String,
    code: String,
    reply: Reply,
    deadline: Instant,
}

struct AccessRequest {
    client: String,
    request_id: String,
    login_id: String,
    url: String,
    fields: Vec<String>,
    text: String,
    reply: Reply,
    deadline: Instant,
}

#[derive(Default)]
pub struct Browser {
    waiting: Vec<Waiting>,
    pair: Option<PairRequest>,
    access: VecDeque<AccessRequest>,
    replay: ReplayGuard,
    /// The window was brought up for the browser (and goes back afterwards).
    popped: bool,
    /// Dialog that was open when a browser question interrupted it.
    return_dialog: Option<Dialog>,
}

fn now() -> i64 {
    otp::now_unix() as i64
}

// ------------------------------------------------------------------ server

/// Starts listening for the extension's host. Runs even while the
/// integration is off, to answer "disabled" instead of timing out.
pub fn start(ui: &AppWindow) {
    let weak = ui.as_weak();
    let served = ipc::serve(move |mut stream| {
        loop {
            let Ok(Some(message)) = ipc::read_frame(&mut stream) else { return };
            let (sender, receiver) = sync_channel(1);
            let weak = weak.clone();
            let posted = slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    incoming(&ui, &message, Reply(sender));
                }
            });
            if posted.is_err() {
                return;
            }
            let reply = receiver
                .recv_timeout(WAIT_LIMIT + Duration::from_secs(30))
                .unwrap_or_else(|_| plain_error("cancelled"));
            if ipc::write_frame(&mut stream, &reply).is_err() {
                return;
            }
        }
    });
    if let Err(e) = served {
        eprintln!("Browser integration unavailable: {e}");
    }

    // Keep the installed helper in step with this version of the app.
    if with_state(|s| s.prefs.browser_enabled) {
        install_in_background(ui, false);
    }
}

fn incoming(ui: &AppWindow, message: &[u8], reply: Reply) {
    let Ok(envelope) = serde_json::from_slice::<Envelope>(message) else {
        reply.error("bad-request");
        return;
    };
    touch();
    let pop = with_state(|s| handle(ui, s, envelope, reply));
    if pop {
        pop_window(ui);
    }
}

fn valid_client(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Handles one message; returns true if the window must come up.
fn handle(ui: &AppWindow, s: &mut State, envelope: Envelope, reply: Reply) -> bool {
    if !s.prefs.browser_enabled {
        reply.error("disabled");
        return false;
    }
    if !matches!(envelope.kind.as_str(), "pair" | "request") || !valid_client(&envelope.client) {
        reply.error("bad-request");
        return false;
    }
    if s.vault.is_none() {
        if envelope.kind == "pair" || envelope.wait {
            if s.browser.waiting.len() >= MAX_WAITING {
                reply.error("busy");
                return false;
            }
            let hint = if envelope.kind == "pair" {
                "A browser wants to connect to Authenticator. Unlock to see the request."
            } else {
                "Your browser is asking for a login. Unlock to continue."
            };
            app(ui).set_lock_hint(hint.into());
            s.browser.waiting.push(Waiting { envelope, reply, deadline: Instant::now() + WAIT_LIMIT });
            return true;
        }
        reply.error("locked");
        return false;
    }
    if envelope.kind == "pair" { pair(ui, s, envelope, reply) } else { request(ui, s, envelope, reply) }
}

/// Brings the window up for the browser.
fn pop_window(ui: &AppWindow) {
    with_state(|s| {
        if !s.window_visible {
            s.browser.popped = true;
        }
    });
    window::show(ui);
}

/// Sends the window back to the notification area if it only came up for
/// the browser and nothing is left to answer.
fn maybe_rehide(ui: &AppWindow) {
    let hide = with_state(|s| {
        let b = &mut s.browser;
        let idle = b.waiting.is_empty() && b.pair.is_none() && b.access.is_empty();
        if b.popped && idle && s.vault.is_some() && app(ui).get_dialog() == Dialog::None {
            b.popped = false;
            true
        } else {
            false
        }
    });
    if hide {
        window::hide(ui);
    }
}

/// Called once the vault is open: answers the requests that were waiting.
pub fn after_unlock(ui: &AppWindow) {
    let pop = with_state(|s| {
        app(ui).set_lock_hint("".into());
        let waiting = std::mem::take(&mut s.browser.waiting);
        let mut pop = false;
        for w in waiting {
            if Instant::now() < w.deadline {
                pop |= handle(ui, s, w.envelope, w.reply);
            } else {
                w.reply.error("timeout");
            }
        }
        pop
    });
    if pop {
        pop_window(ui);
    } else {
        maybe_rehide(ui);
    }
}

/// Called when the app locks: questions on screen are answered "locked".
pub fn on_lock(s: &mut State) {
    if let Some(p) = s.browser.pair.take() {
        p.reply.error("locked");
    }
    for r in s.browser.access.drain(..) {
        r.reply.error("locked");
    }
    s.browser.return_dialog = None;
}

/// Called when the user hides the window: nothing is waiting for it any more.
pub fn on_hidden(ui: &AppWindow, s: &mut State) {
    for w in s.browser.waiting.drain(..) {
        w.reply.error("cancelled");
    }
    if let Some(p) = s.browser.pair.take() {
        p.reply.error("denied");
    }
    for r in s.browser.access.drain(..) {
        r.reply.error("denied");
    }
    s.browser.popped = false;
    if let Some(back) = s.browser.return_dialog.take() {
        open_dialog(ui, back);
    }
    app(ui).set_lock_hint("".into());
}

/// Drops requests that waited too long (called by the timer).
pub fn expire(ui: &AppWindow) {
    let mut changed = false;
    try_with_state(|s| {
        let now = Instant::now();
        let b = &mut s.browser;
        if b.waiting.iter().any(|w| w.deadline <= now) {
            let (expired, kept): (Vec<_>, Vec<_>) =
                std::mem::take(&mut b.waiting).into_iter().partition(|w| w.deadline <= now);
            b.waiting = kept;
            for w in expired {
                w.reply.error("timeout");
            }
            if b.waiting.is_empty() {
                app(ui).set_lock_hint("".into());
            }
            changed = true;
        }
        let mut answered = false;
        if b.pair.as_ref().is_some_and(|p| p.deadline <= now) {
            b.pair.take().expect("checked").reply.error("timeout");
            answered = true;
        }
        if let Some(r) = b.access.pop_front_if(|r| r.deadline <= now) {
            r.reply.error("timeout");
            answered = true;
        }
        if answered {
            finish_question(ui, s);
            changed = true;
        }
    });
    if changed {
        maybe_rehide(ui);
    }
}

// ------------------------------------------------------------------ questions in the app

/// Shows the next browser question (connecting, or giving a password), if any.
fn show_question(ui: &AppWindow, s: &mut State) {
    let a = app(ui);
    let current = a.get_dialog();
    if matches!(current, Dialog::Pair | Dialog::ConfirmAccess) {
        return;
    }
    let next = if let Some(p) = &s.browser.pair {
        a.set_pair_name(p.name.as_str().into());
        a.set_pair_code(p.code.as_str().into());
        Dialog::Pair
    } else if let Some(r) = s.browser.access.front() {
        a.set_access_text(r.text.as_str().into());
        Dialog::ConfirmAccess
    } else {
        return;
    };
    if s.browser.return_dialog.is_none() {
        s.browser.return_dialog = Some(current);
    }
    open_dialog(ui, next);
}

/// After a question was answered: the next one, or back to what was open.
fn finish_question(ui: &AppWindow, s: &mut State) {
    let a = app(ui);
    if matches!(a.get_dialog(), Dialog::Pair | Dialog::ConfirmAccess) {
        a.set_dialog(Dialog::None);
    }
    if s.browser.pair.is_some() || !s.browser.access.is_empty() {
        show_question(ui, s);
    } else if let Some(back) = s.browser.return_dialog.take() {
        open_dialog(ui, back);
        if back == Dialog::None {
            ui.invoke_focus_list();
        }
    }
}

fn pair(ui: &AppWindow, s: &mut State, envelope: Envelope, reply: Reply) -> bool {
    let Some(key) = browser::decode_key(&envelope.key) else {
        reply.error("bad-request");
        return false;
    };
    if s.browser.pair.is_some() {
        reply.error("busy");
        return false;
    }
    let name: String = envelope.name.trim().chars().filter(|c| !c.is_control()).take(60).collect();
    s.browser.pair = Some(PairRequest {
        client: envelope.client,
        name: if name.is_empty() { "A browser".into() } else { name },
        key: envelope.key.trim().to_string(),
        code: browser::pair_code(&key[..]),
        reply,
        deadline: Instant::now() + WAIT_LIMIT,
    });
    show_question(ui, s);
    true
}

fn answer_pair(ui: &AppWindow, allow: bool) {
    with_state(|s| {
        let Some(p) = s.browser.pair.take() else { return };
        if !allow {
            p.reply.error("denied");
        } else if let Some(vault) = s.vault.as_mut() {
            let now = now();
            vault.browsers.retain(|c| c.id != p.client);
            vault.browsers.push(BrowserClient {
                id: p.client,
                name: p.name.clone(),
                key: p.key,
                created: now,
                last_used: now,
            });
            if save(ui, s) {
                p.reply.send(serde_json::to_vec(&json!({ "type": "paired" })).expect("serializable"));
                toast(ui, false, format!("{} is connected.", p.name));
            } else {
                p.reply.error("save-failed");
            }
        } else {
            p.reply.error("locked");
        }
        refresh_clients(ui, s);
        finish_question(ui, s);
    });
    maybe_rehide(ui);
}

fn answer_access(ui: &AppWindow, allow: bool) {
    with_state(|s| {
        let Some(r) = s.browser.access.pop_front() else { return };
        if !allow {
            r.reply.error("denied");
        } else {
            let fill = fill_values(ui, s, &r.login_id, &r.url, &r.fields);
            respond(s, &r.client, &r.request_id, r.reply, fill);
        }
        finish_question(ui, s);
    });
    maybe_rehide(ui);
}

// ------------------------------------------------------------------ requests

/// Encrypts an answer for the client.
fn respond(s: &State, client: &str, request_id: &str, reply: Reply, mut body: Value) {
    let Some(key) = s
        .vault
        .as_ref()
        .and_then(|v| v.browsers.iter().find(|c| c.id == client))
        .and_then(|c| browser::decode_key(&c.key))
    else {
        reply.error("unknown-client");
        return;
    };
    body["id"] = json!(request_id);
    let plain = Zeroizing::new(serde_json::to_vec(&body).expect("serializable"));
    let (nonce, data) = browser::seal(&key, client, Direction::Response, &plain);
    reply.send(serde_json::to_vec(&json!({ "type": "response", "nonce": nonce, "data": data })).expect("serializable"));
}

fn failure(error: &str) -> Value {
    json!({ "ok": false, "error": error })
}

fn request(ui: &AppWindow, s: &mut State, envelope: Envelope, reply: Reply) -> bool {
    let client = envelope.client.clone();
    let vault = s.vault.as_mut().expect("unlocked");
    let Some(index) = vault.browsers.iter().position(|c| c.id == client) else {
        reply.error("unknown-client");
        return false;
    };
    let Some(key) = browser::decode_key(&vault.browsers[index].key) else {
        reply.error("unknown-client");
        return false;
    };
    let Some(plain) = browser::open(&key, &client, Direction::Request, &envelope.nonce, &envelope.data) else {
        reply.error("bad-request");
        return false;
    };
    let Ok(req) = serde_json::from_slice::<Request>(&plain) else {
        reply.error("bad-request");
        return false;
    };
    let now = now();
    if !s.browser.replay.check(&client, &req.id, req.ts, now) {
        reply.error("expired");
        return false;
    }
    let vault = s.vault.as_mut().expect("unlocked");
    let browser_client = &mut vault.browsers[index];
    let save_use = now - browser_client.last_used > 3600;
    browser_client.last_used = now;
    let client_name = browser_client.name.clone();
    if save_use {
        save(ui, s);
    }

    let body = match req.action.as_str() {
        "status" | "unlock" => json!({ "ok": true, "name": client_name }),
        "logins" => logins_for(s, &req.url),
        "fill" => {
            let fields: Vec<String> = ["username", "password", "otp"]
                .iter()
                .filter(|f| req.fields.iter().any(|r| r == *f))
                .map(|f| f.to_string())
                .collect();
            let vault = s.vault.as_ref().expect("unlocked");
            match vault.logins.iter().find(|l| l.id == req.login) {
                None => failure("not-found"),
                Some(login) if match_score(&login.url, &req.url).is_none() => failure("not-allowed"),
                Some(_) if fields.is_empty() => failure("bad-request"),
                Some(login) if vault.settings.confirm_browser_access => {
                    let text = access_text(&client_name, login, &req.url, &fields);
                    s.browser.access.push_back(AccessRequest {
                        client,
                        request_id: req.id.clone(),
                        login_id: req.login.clone(),
                        url: req.url.clone(),
                        fields,
                        text,
                        reply,
                        deadline: Instant::now() + WAIT_LIMIT,
                    });
                    show_question(ui, s);
                    return true;
                }
                Some(_) => fill_values(ui, s, &req.login, &req.url, &fields),
            }
        }
        "save" => save_login(ui, s, &req),
        _ => failure("unknown-action"),
    };
    respond(s, &client, &req.id, reply, body);
    false
}

fn logins_for(s: &State, url: &str) -> Value {
    let vault = s.vault.as_ref().expect("unlocked");
    let logins: Vec<LoginSummary> = browser::matching_logins(&vault.logins, url)
        .into_iter()
        .take(MAX_LOGINS)
        .map(|l| LoginSummary {
            id: l.id.clone(),
            title: l.display_title(),
            username: l.username.clone(),
            otp: !l.otp.is_empty() && vault.entries.iter().any(|a| a.id == l.otp),
        })
        .collect();
    json!({ "ok": true, "logins": logins })
}

fn access_text(client: &str, login: &Login, url: &str, fields: &[String]) -> String {
    let what: Vec<&str> = fields
        .iter()
        .map(|f| match f.as_str() {
            "username" => "user name",
            "password" => "password",
            _ => "2FA code",
        })
        .collect();
    let what = match what.as_slice() {
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
        [] => String::new(),
    };
    let host = Site::parse(url).map(|s| s.host).unwrap_or_default();
    let user = if login.username.is_empty() { String::new() } else { format!(" ({})", login.username) };
    format!("{client} asks for the {what} of \"{}\"{user} to sign in on {host}.", login.display_title())
}

/// The requested fields of a login, checked again against the page.
fn fill_values(ui: &AppWindow, s: &mut State, login_id: &str, url: &str, fields: &[String]) -> Value {
    let Some(vault) = s.vault.as_mut() else { return failure("locked") };
    let Some(login) = vault.logins.iter().find(|l| l.id == login_id) else { return failure("not-found") };
    if match_score(&login.url, url).is_none() {
        return failure("not-allowed");
    }
    let mut body = json!({ "ok": true });
    let wants = |f: &str| fields.iter().any(|x| x == f);
    if wants("username") {
        body["username"] = json!(login.username);
    }
    if wants("password") {
        body["password"] = json!(login.password.as_str());
    }
    let mut counter_used = false;
    if wants("otp") && !login.otp.is_empty() {
        let otp_id = login.otp.clone();
        if let Some(account) = vault.entries.iter_mut().find(|a| a.id == otp_id) {
            let now = otp::now_unix();
            body["otp"] = json!(account.code_at(now));
            if account.kind == OtpKind::Totp {
                body["otp_remaining"] = json!(account.seconds_remaining(now));
            } else {
                // A counter-based code can only be used once.
                account.counter += 1;
                counter_used = true;
            }
        }
    }
    if counter_used && save(ui, s) {
        codes::refresh(ui, s, None);
    }
    body
}

fn save_login(ui: &AppWindow, s: &mut State, req: &Request) -> Value {
    let Some(site) = Site::parse(&req.url).filter(|site| site.scheme == "https" || site.scheme == "http") else {
        return failure("bad-url");
    };
    if req.password.is_empty() {
        return failure("empty-password");
    }
    let origin = match site.port {
        Some(port) => format!("{}://{}:{port}", site.scheme, site.host),
        None => format!("{}://{}", site.scheme, site.host),
    };
    let username: String = req.username.trim().to_string();
    let now = now();
    let vault = s.vault.as_mut().expect("unlocked");
    let existing = vault.logins.iter().position(|l| l.host() == site.host && l.username == username);
    let updated = existing.is_some();
    let mut login = match existing {
        Some(i) => vault.logins[i].clone(),
        None => Login {
            id: crypto::new_id(),
            title: {
                let title = req.title.trim();
                if title.is_empty() {
                    site.host.strip_prefix("www.").unwrap_or(&site.host).to_string()
                } else {
                    title.chars().take(256).collect()
                }
            },
            username,
            url: origin,
            created: now,
            ..Default::default()
        },
    };
    login.password = req.password.clone();
    login.modified = now;
    if let Err(e) = login.validate() {
        return json!({ "ok": false, "error": "invalid", "message": e });
    }
    let title = login.display_title();
    match existing {
        Some(i) => vault.logins[i] = login,
        None => {
            vault.logins.push(login);
            let id = session::next_id(s);
            s.login_ids.push(id);
        }
    }
    if !save(ui, s) {
        return failure("save-failed");
    }
    refresh_all(ui, s);
    toast(ui, false, format!("Saved the password for \"{title}\" from the browser."));
    json!({ "ok": true, "updated": updated })
}

// ------------------------------------------------------------------ the "Browser integration" dialog

fn refresh_clients(ui: &AppWindow, s: &State) {
    let rows: Vec<BrowserRow> = s
        .vault
        .as_ref()
        .map(|v| {
            let mut clients: Vec<&BrowserClient> = v.browsers.iter().collect();
            clients.sort_by_key(|c| std::cmp::Reverse(c.last_used));
            clients
                .into_iter()
                .map(|c| BrowserRow {
                    id: c.id.as_str().into(),
                    name: c.name.as_str().into(),
                    detail: format!(
                        "Connected {} · last used {}",
                        platform::local_date(c.created),
                        platform::local_date(c.last_used)
                    )
                    .into(),
                })
                .collect()
        })
        .unwrap_or_default();
    app(ui).set_browser_clients(ModelRc::new(VecModel::from(rows)));
}

fn set_status(ui: &AppWindow, error: bool, text: impl Into<String>) {
    let a = app(ui);
    a.set_browser_status(text.into().into());
    a.set_browser_status_error(error);
}

fn status_text(enabled: bool) -> &'static str {
    if enabled {
        "On. Browsers with the extension can ask for your logins while Authenticator is unlocked."
    } else {
        "Off. Browsers cannot reach Authenticator."
    }
}

fn install_in_background(ui: &AppWindow, report_success: bool) {
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let result = install::install();
        let _ = weak.upgrade_in_event_loop(move |ui| match result {
            Ok(paths) => {
                app(&ui).set_browser_folder(paths.extension.display().to_string().into());
                if report_success {
                    set_status(&ui, false, status_text(true));
                }
            }
            Err(e) => set_status(&ui, true, e),
        });
    });
}

fn open_browser_dialog(ui: &AppWindow) {
    let a = app(ui);
    let enabled = with_state(|s| {
        refresh_clients(ui, s);
        s.prefs.browser_enabled
    });
    a.set_browser_enabled(enabled);
    a.set_browser_folder(install::paths().extension.display().to_string().into());
    if !a.get_browser_status_error() || !enabled {
        set_status(ui, false, status_text(enabled));
    }
    open_dialog(ui, Dialog::Browser);
}

fn set_enabled(ui: &AppWindow, enabled: bool) {
    with_state(|s| {
        s.prefs.browser_enabled = enabled;
        save_prefs(ui, s);
        if !enabled {
            for w in s.browser.waiting.drain(..) {
                w.reply.error("disabled");
            }
            app(ui).set_lock_hint("".into());
        }
    });
    app(ui).set_browser_enabled(enabled);
    if enabled {
        set_status(ui, false, "Installing…");
        install_in_background(ui, true);
    } else {
        install::uninstall();
        set_status(ui, false, status_text(false));
    }
}

pub fn wire(ui: &AppWindow) {
    callback!(ui, on_open_browser, |ui| open_browser_dialog(&ui));
    callback!(ui, on_browser_toggled, |ui, on| set_enabled(&ui, on));
    callback!(ui, on_browser_open_folder, |ui| {
        let folder = install::paths().extension;
        if !folder.exists() || !platform::open_external(folder.as_os_str()) {
            report(&ui, true, "The folder is not there yet. Turn the integration off and on again.");
        }
    });
    callback!(ui, on_browser_copy_path, |ui| {
        let folder = install::paths().extension.display().to_string();
        let result = with_state(|s| clipboard(s).and_then(|cb| cb.set_text(folder).map_err(|e| e.to_string())));
        match result {
            Ok(()) => report(&ui, false, "Folder path copied."),
            Err(e) => report(&ui, true, format!("Could not copy: {e}")),
        }
    });
    callback!(ui, on_browser_remove, |ui, id| with_state(|s| {
        let Some(vault) = s.vault.as_mut() else { return };
        let before = vault.browsers.len();
        vault.browsers.retain(|c| c.id != id.as_str());
        if vault.browsers.len() != before && save(&ui, s) {
            report(&ui, false, "Disconnected. That browser must be connected again to fill in logins.");
        }
        refresh_clients(&ui, s);
    }));
    callback!(ui, on_pair_answer, |ui, allow| answer_pair(&ui, allow));
    callback!(ui, on_access_answer, |ui, allow| answer_access(&ui, allow));
}
