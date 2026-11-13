//! The 2FA codes list: rows, adding (QR, setup key, link), editing, deleting.

use std::time::Duration;

use authenticator::otp::{self, Account, Algorithm, OtpKind, Secret};
use authenticator::vault::Vault;
use authenticator::{ImportResult, base32, merge, parse_import_text, platform, qr};
use slint::{ComponentHandle, Model, Timer};
use zeroize::Zeroizing;

use super::session::next_id;
use super::*;

pub fn format_code(code: &str) -> String {
    match code.len() {
        6 | 7 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_string(),
    }
}

/// (title, account) shown for an account: the service and the user name.
pub fn titles(a: &Account) -> (String, String) {
    if a.issuer.trim().is_empty() { (a.display_title(), String::new()) } else { (a.issuer.clone(), a.name.clone()) }
}

pub fn describe(a: &Account) -> String {
    match a.kind {
        OtpKind::Totp => {
            format!("Time-based (TOTP) · {} · {} digits · new code every {} s", a.algorithm.name(), a.digits, a.period)
        }
        OtpKind::Hotp => {
            format!("Counter-based (HOTP) · {} · {} digits · next counter {}", a.algorithm.name(), a.digits, a.counter)
        }
    }
}

/// Code, seconds left, fraction of the period left and "about to change".
pub fn live(a: &Account, now: u64) -> (String, i32, f32, bool) {
    let totp = a.kind == OtpKind::Totp;
    let remaining = if totp { a.seconds_remaining(now) as i32 } else { 0 };
    let progress = if totp { remaining as f32 / a.period.max(1) as f32 } else { 0.0 };
    (format_code(&a.code_at(now)), remaining, progress, totp && remaining <= 5)
}

fn make_row(id: i32, a: &Account, vault: &Vault, now: u64) -> CodeRow {
    let (title, account) = titles(a);
    let (code, remaining, progress, warn) = live(a, now);
    let used_by: Vec<String> =
        vault.logins.iter().filter(|l| !a.id.is_empty() && l.otp == a.id).map(|l| l.display_title()).collect();
    CodeRow {
        id,
        initial: first_letter(&title),
        title: title.into(),
        account: account.into(),
        code: code.into(),
        remaining,
        progress,
        hotp: a.kind == OtpKind::Hotp,
        warn,
        info: describe(a).into(),
        used_by: used_by.join(", ").into(),
    }
}

pub fn index_of(s: &State, id: i32) -> Option<usize> {
    s.code_ids.iter().position(|&x| x == id)
}

/// Rebuilds the list. `select` picks a row by id; otherwise the selection is kept.
pub fn refresh(ui: &AppWindow, s: &mut State, select: Option<i32>) {
    let a = app(ui);
    let keep = select.or_else(|| selected_id(&s.code_rows, a.get_code_index(), |r: &CodeRow| r.id));
    let now = otp::now_unix();
    let filter = s.filter.trim().to_lowercase();
    let mut rows = Vec::new();
    s.visible_codes.clear();
    if let Some(vault) = s.vault.as_ref() {
        for (i, account) in vault.entries.iter().enumerate() {
            let matches = filter.is_empty()
                || account.issuer.to_lowercase().contains(&filter)
                || account.name.to_lowercase().contains(&filter);
            if matches {
                s.visible_codes.push(i);
                rows.push(make_row(s.code_ids[i], account, vault, now));
            }
        }
    }
    let index = keep.and_then(|id| rows.iter().position(|r| r.id == id)).map(|i| i as i32).unwrap_or(-1);
    s.code_rows.set_vec(rows);
    a.set_code_index(index);
    a.set_code_total(s.vault.as_ref().map(|v| v.entries.len()).unwrap_or(0) as i32);
}

/// Called every second: new codes and countdowns.
pub fn update_rows(s: &State, now: u64) {
    let Some(vault) = s.vault.as_ref() else {
        return;
    };
    for (row, &index) in s.visible_codes.iter().enumerate() {
        let (Some(account), Some(mut data)) = (vault.entries.get(index), s.code_rows.row_data(row)) else {
            continue;
        };
        let (code, remaining, progress, warn) = live(account, now);
        if data.code != code.as_str() || data.remaining != remaining || data.warn != warn {
            data.code = code.into();
            data.remaining = remaining;
            data.progress = progress;
            data.warn = warn;
            s.code_rows.set_row_data(row, data);
        }
    }
}

// ------------------------------------------------------------------ adding

pub fn import_accounts(ui: &AppWindow, accounts: Vec<Account>, messages: Vec<String>, batch: Option<(u32, u32)>) {
    let a = app(ui);
    let outcome = with_state(|s| {
        let vault = s.vault.as_mut()?;
        let before = vault.entries.len();
        let result = merge::merge(&mut vault.entries, &mut vault.logins, accounts, Vec::new());
        let added = vault.entries.len() - before;
        for _ in 0..added {
            let id = next_id(s);
            s.code_ids.push(id);
        }
        let saved = (added == 0 && result.accounts_skipped == 0) || save(ui, s);
        a.set_section(Section::Codes);
        let last = if added > 0 { s.code_ids.last().copied() } else { None };
        refresh(ui, s, last);
        saved.then_some((added, result.accounts_skipped))
    });
    let Some((added, duplicates)) = outcome else {
        return;
    };
    let mut text = match (added, duplicates) {
        (0, 0) => "Nothing to add.".to_string(),
        (0, 1) => "This account is already in the list.".to_string(),
        (0, d) => format!("All {d} accounts are already in the list."),
        (n, 0) => format!("Added {}.", plural(n, "account")),
        (n, d) => format!("Added {} ({d} already in the list).", plural(n, "account")),
    };
    for message in &messages {
        text.push_str(&format!("\nSkipped {message}"));
    }
    match batch {
        Some((index, size)) if index < size => {
            open_dialog(ui, Dialog::AddCode);
            report(
                ui,
                false,
                format!(
                    "{text}\nThat was QR code {index} of {size} from Google Authenticator. Now add code {}.",
                    index + 1
                ),
            );
        }
        _ if added > 0 && messages.is_empty() => {
            if a.get_dialog() == Dialog::AddCode {
                close_dialog(ui);
            }
            toast(ui, false, text);
        }
        _ => report(ui, added == 0 && duplicates == 0, text),
    }
}

pub fn import_texts(ui: &AppWindow, texts: Vec<String>) {
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
            app(&ui).set_busy(false);
            match result {
                Ok(texts) if texts.is_empty() => {
                    report(&ui, true, "No QR code found. Make sure the whole QR code is visible and not cut off.")
                }
                Ok(texts) => import_texts(&ui, texts),
                Err(e) => report(&ui, true, e),
            }
        });
    });
}

fn paste_image(ui: &AppWindow) {
    match with_state(clipboard_content) {
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

#[allow(clippy::too_many_arguments)]
fn add_manual(
    ui: &AppWindow,
    issuer: &str,
    name: &str,
    secret: &str,
    kind: i32,
    algorithm: i32,
    digits: i32,
    number: &str,
) -> Result<(), String> {
    if issuer.trim().is_empty() && name.trim().is_empty() {
        return Err("Enter the service or account name.".into());
    }
    let secret = base32::decode(secret)?;
    let kind = if kind == 1 { OtpKind::Hotp } else { OtpKind::Totp };
    let Ok(number) = number.trim().parse::<u64>() else {
        return Err(if kind == OtpKind::Totp {
            "The period must be a number of seconds.".into()
        } else {
            "The counter must be a number.".into()
        });
    };
    let account = Account {
        id: String::new(),
        kind,
        issuer: issuer.trim().to_string(),
        name: name.trim().to_string(),
        secret: Secret::new(secret),
        algorithm: [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512][algorithm.clamp(0, 2) as usize],
        digits: [6, 7, 8][digits.clamp(0, 2) as usize],
        period: if kind == OtpKind::Totp { number.min(u32::MAX as u64) as u32 } else { 30 },
        counter: if kind == OtpKind::Hotp { number } else { 0 },
    };
    account.validate()?;
    import_accounts(ui, vec![account], Vec::new(), None);
    Ok(())
}

// ------------------------------------------------------------------ editing

fn open_editor(ui: &AppWindow, id: i32, confirm_delete: bool) {
    let a = app(ui);
    let found = with_state(|s| {
        let index = index_of(s, id)?;
        let vault = s.vault.as_ref()?;
        let account = &vault.entries[index];
        let mut info = describe(account);
        let users: Vec<String> =
            vault.logins.iter().filter(|l| l.otp == account.id).map(|l| l.display_title()).collect();
        if !users.is_empty() {
            info.push_str(&format!(
                "\nLinked to the saved {} {}.",
                if users.len() == 1 { "login" } else { "logins" },
                users.join(", ")
            ));
        }
        a.set_edit_code_id(id);
        a.set_edit_issuer(account.issuer.as_str().into());
        a.set_edit_name(account.name.as_str().into());
        a.set_edit_code_info(info.into());
        Some(())
    });
    if found.is_some() {
        open_dialog(ui, Dialog::EditCode);
        a.set_confirm_delete(confirm_delete);
    }
}

pub fn wire(ui: &AppWindow) {
    callback!(ui, on_copy_code, |ui, id| with_state(|s| {
        let Some(index) = index_of(s, id) else { return };
        let Some(vault) = s.vault.as_ref() else {
            return;
        };
        let code = Zeroizing::new(vault.entries[index].code_at(otp::now_unix()));
        copy_secret(&ui, s, code, "Code");
    }));

    callback!(ui, on_next_hotp, |ui, id| with_state(|s| {
        let Some(index) = index_of(s, id) else { return };
        if let Some(vault) = s.vault.as_mut() {
            vault.entries[index].counter += 1;
        }
        save(&ui, s);
        refresh(&ui, s, None);
    }));

    callback!(ui, on_edit_code, |ui, id| open_editor(&ui, id, false));
    callback!(ui, on_ask_delete_code, |ui, id| open_editor(&ui, id, true));

    callback!(ui, on_save_code, |ui| {
        let a = app(&ui);
        let id = a.get_edit_code_id();
        with_state(|s| {
            let Some(index) = index_of(s, id) else { return };
            if let Some(vault) = s.vault.as_mut() {
                let entry = &mut vault.entries[index];
                entry.issuer = a.get_edit_issuer().trim().chars().take(256).collect();
                entry.name = a.get_edit_name().trim().chars().take(256).collect();
            }
            if save(&ui, s) {
                refresh_all(&ui, s);
            }
        });
        close_dialog(&ui);
    });

    callback!(ui, on_delete_code, |ui, id| {
        let deleted = with_state(|s| {
            let index = index_of(s, id)?;
            let vault = s.vault.as_mut()?;
            let account = vault.entries.remove(index);
            for login in vault.logins.iter_mut().filter(|l| l.otp == account.id) {
                login.otp.clear();
            }
            s.code_ids.remove(index);
            let ok = save(&ui, s);
            refresh_all(&ui, s);
            Some(ok)
        });
        close_dialog(&ui);
        if deleted == Some(true) {
            toast(&ui, false, "2FA code deleted.");
        }
    });

    callback!(ui, on_paste_image, |ui| paste_image(&ui));
    callback!(ui, on_scan_screen, |ui| scan_screen(&ui));

    callback!(ui, on_open_image, |ui| {
        if let Some(path) = dialogs::open_image(&ui) {
            decode_in_background(&ui, "Looking for a QR code…", move || qr::decode_file(&path));
        }
    });

    callback!(ui, on_add_manual, |ui, issuer, name, secret, kind, algorithm, digits, number| {
        if let Err(e) = add_manual(&ui, &issuer, &name, &secret, kind, algorithm, digits, &number) {
            report(&ui, true, e);
        }
    });

    callback!(ui, on_add_link, |ui, text| {
        if !text.trim().is_empty() {
            import_texts(&ui, vec![text.to_string()]);
        }
    });
}
