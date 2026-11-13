//! Moving data in and out: QR codes, encrypted backup files, restoring.
//! Showing secrets (QR codes, backups) asks for the PIN again first.

use std::time::{Duration, Instant};

use authenticator::otp::{Account, OtpKind};
use authenticator::{backup, crypto, merge, migration, platform, qr};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use zeroize::Zeroizing;

use super::codes::titles;
use super::session::{next_id, pin_wait, wrong_pin};
use super::*;

const MAX_BACKUP_FILE: u64 = 20 * 1024 * 1024;
/// After the PIN is confirmed, exporting works without asking again for this long.
const CONFIRM_GRACE: Duration = Duration::from_secs(120);

fn qr_image(text: &str) -> Option<slint::Image> {
    let bitmap = qr::encode(text).ok()?;
    let scale = (720 / bitmap.size).max(1);
    let side = bitmap.size * scale;
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(side as u32, side as u32);
    let pixels = buffer.make_mut_slice();
    for y in 0..side {
        for x in 0..side {
            let dark = bitmap.dark[(y / scale) * bitmap.size + x / scale];
            let v = if dark { 0 } else { 255 };
            pixels[y * side + x] = slint::Rgb8Pixel { r: v, g: v, b: v };
        }
    }
    Some(slint::Image::from_rgb8(buffer))
}

// ------------------------------------------------------------------ PIN check

fn require_pin(ui: &AppWindow, action: Pending) {
    let confirmed = with_state(|s| {
        if s.confirmed_until.is_some_and(|t| Instant::now() < t) {
            true
        } else {
            s.pending = Some(action);
            false
        }
    });
    if confirmed {
        run(ui, action);
        return;
    }
    app(ui).set_pin_reason(
        match action {
            Pending::Export => "Exporting shows your secret keys and passwords. Enter your PIN to continue.",
            Pending::CodeQr(_) => "The QR code contains the secret key of this account. Enter your PIN to show it.",
        }
        .into(),
    );
    open_dialog(ui, Dialog::Pin);
}

fn run(ui: &AppWindow, action: Pending) {
    match action {
        Pending::Export => open_export(ui),
        Pending::CodeQr(id) => show_code_qr(ui, id),
    }
}

fn pin_entered(ui: &AppWindow, pin: Zeroizing<String>) {
    if pin.is_empty() {
        return;
    }
    if let Some(wait) = with_state(|s| pin_wait(s)) {
        return report(ui, true, format!("Too many wrong attempts. Try again in {wait} s."));
    }
    let Some(check) = with_state(|s| s.vault.as_ref().map(|v| v.pin_check())) else {
        return;
    };
    set_busy(ui, "Checking…");
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let ok = check.verify(&pin);
        let _ = weak.upgrade_in_event_loop(move |ui| {
            app(&ui).set_busy(false);
            let action = with_state(|s| {
                if ok {
                    s.failed_attempts = 0;
                    s.locked_until = None;
                    s.confirmed_until = Some(Instant::now() + CONFIRM_GRACE);
                    Ok(s.pending.take())
                } else {
                    Err(wrong_pin(s))
                }
            });
            match action {
                Ok(Some(action)) if app(&ui).get_dialog() == Dialog::Pin => run(&ui, action),
                Ok(_) => {}
                Err(message) => report(&ui, true, message),
            }
        });
    });
}

// ------------------------------------------------------------------ export

fn count_checked(model: &VecModel<PickRow>) -> i32 {
    model.iter().filter(|r| r.checked).count() as i32
}

fn update_counts(ui: &AppWindow, s: &State) {
    let a = app(ui);
    a.set_export_code_count(count_checked(&s.export_codes));
    a.set_export_login_count(count_checked(&s.export_logins));
}

fn open_export(ui: &AppWindow) {
    let ok = with_state(|s| {
        let Some(vault) = s.vault.as_ref() else {
            return false;
        };
        let codes: Vec<PickRow> = vault
            .entries
            .iter()
            .zip(&s.code_ids)
            .map(|(account, &id)| {
                let (title, name) = titles(account);
                PickRow { id, title: title.into(), subtitle: name.into(), checked: true }
            })
            .collect();
        let mut logins: Vec<(String, PickRow)> = vault
            .logins
            .iter()
            .zip(&s.login_ids)
            .map(|(login, &id)| {
                let title = login.display_title();
                let subtitle = if login.username.is_empty() { login.host() } else { login.username.clone() };
                (title.to_lowercase(), PickRow { id, title: title.into(), subtitle: subtitle.into(), checked: true })
            })
            .collect();
        logins.sort_by(|a, b| a.0.cmp(&b.0));
        s.export_codes.set_vec(codes);
        s.export_logins.set_vec(logins.into_iter().map(|(_, row)| row).collect::<Vec<_>>());
        update_counts(ui, s);
        true
    });
    if ok {
        open_dialog(ui, Dialog::Export);
    }
}

/// The accounts and logins ticked in the export dialog.
fn selection(s: &State) -> (Vec<Account>, Vec<authenticator::login::Login>) {
    let Some(vault) = s.vault.as_ref() else {
        return Default::default();
    };
    let ids = |model: &VecModel<PickRow>| model.iter().filter(|r| r.checked).map(|r| r.id).collect::<Vec<_>>();
    let accounts: Vec<Account> = ids(&s.export_codes)
        .into_iter()
        .filter_map(|id| s.code_ids.iter().position(|&x| x == id))
        .map(|i| vault.entries[i].clone())
        .collect();
    let mut logins: Vec<authenticator::login::Login> = ids(&s.export_logins)
        .into_iter()
        .filter_map(|id| s.login_ids.iter().position(|&x| x == id))
        .map(|i| vault.logins[i].clone())
        .collect();
    // Links to 2FA codes that are not exported would point nowhere.
    for login in &mut logins {
        if !login.otp.is_empty() && !accounts.iter().any(|a| a.id == login.otp) {
            login.otp.clear();
        }
    }
    (accounts, logins)
}

fn export_qr(ui: &AppWindow) {
    let a = app(ui);
    let found = with_state(|s| {
        let (accounts, _) = selection(s);
        let exportable: Vec<&Account> = accounts.iter().filter(|a| migration::exportable(a)).collect();
        let left_out = accounts.len() - exportable.len();
        if exportable.is_empty() {
            return Err("Google Authenticator only supports 30-second codes with 6 or 8 digits. Use \"Show QR code\" on each code, or an encrypted backup file.".to_string());
        }
        let batch_id = i32::from_le_bytes(crypto::random::<4>()) & 0x7fff_ffff;
        let uris = migration::encode_uris(&exportable, batch_id);
        let images: Vec<slint::Image> = uris.iter().filter_map(|u| qr_image(u)).collect();
        let mut note = format!("{} in {}.", plural(exportable.len(), "account"), plural(uris.len(), "QR code"));
        if left_out > 0 {
            note.push_str(&format!(
                " {} left out (settings Google Authenticator does not support): use a backup file or show their QR codes one by one.",
                plural(left_out, "account")
            ));
        }
        s.qr_return = Dialog::Export;
        Ok((images, note))
    });
    match found {
        Ok((images, note)) => {
            a.set_qr_title("Transfer to another app".into());
            a.set_qr_note(note.into());
            a.set_qr_account_id(-1);
            a.set_qr_images(ModelRc::new(VecModel::from(images)));
            a.set_qr_index(0);
            open_dialog(ui, Dialog::Qr);
        }
        Err(e) => report(ui, true, e),
    }
}

/// One account as a standard otpauth:// QR code, for any authenticator app.
fn show_code_qr(ui: &AppWindow, id: i32) {
    let a = app(ui);
    let found = with_state(|s| {
        let index = s.code_ids.iter().position(|&x| x == id)?;
        let account = s.vault.as_ref()?.entries.get(index)?.clone();
        let uri = Zeroizing::new(account.to_otpauth());
        let image = qr_image(&uri)?;
        let (title, name) = titles(&account);
        let mut note = if name.is_empty() { title.clone() } else { format!("{title} · {name}") };
        if !migration::exportable(&account) || account.kind == OtpKind::Hotp {
            note.push_str(" · uses settings some apps (like Google Authenticator) may not support");
        }
        s.qr_return = Dialog::None;
        Some((title, note, image))
    });
    match found {
        Some((title, note, image)) => {
            a.set_qr_title(format!("QR code: {title}").into());
            a.set_qr_note(note.into());
            a.set_qr_account_id(id);
            a.set_qr_images(ModelRc::new(VecModel::from(vec![image])));
            a.set_qr_index(0);
            open_dialog(ui, Dialog::Qr);
        }
        None => report(ui, true, "Could not create the QR code."),
    }
}

fn export_backup(ui: &AppWindow, password: Zeroizing<String>, confirm: &str) {
    if password.chars().count() < backup::MIN_PASSWORD_LEN {
        return report(ui, true, format!("Use a password with at least {} characters.", backup::MIN_PASSWORD_LEN));
    }
    if *password != confirm {
        return report(ui, true, "The two passwords do not match.");
    }
    let (accounts, logins) = with_state(|s| selection(s));
    if accounts.is_empty() && logins.is_empty() {
        return report(ui, true, "Select something to export.");
    }
    let Some(path) = dialogs::save_backup(
        ui,
        &format!("authenticator-backup-{}.json", platform::local_date(authenticator::otp::now_unix() as i64)),
    ) else {
        return;
    };
    set_busy(ui, "Encrypting backup…");
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let result = backup::create(&accounts, &logins, &password)
            .and_then(|contents| std::fs::write(&path, contents).map_err(|e| e.to_string()));
        let what = match (accounts.len(), logins.len()) {
            (a, 0) => plural(a, "2FA code"),
            (0, l) => plural(l, "password"),
            (a, l) => format!("{} and {}", plural(a, "2FA code"), plural(l, "password")),
        };
        let _ = weak.upgrade_in_event_loop(move |ui| {
            app(&ui).set_busy(false);
            match result {
                Ok(()) => report(&ui, false, format!("Backup with {what} saved to {}", path.display())),
                Err(e) => report(&ui, true, format!("Could not save the backup: {e}")),
            }
        });
    });
}

// ------------------------------------------------------------------ restore

fn restore_backup(ui: &AppWindow) {
    let Some(path) = dialogs::open_backup(ui) else {
        return;
    };
    let too_big = std::fs::metadata(&path).map(|m| m.len() > MAX_BACKUP_FILE).unwrap_or(false);
    match std::fs::read(&path) {
        _ if too_big => report(ui, true, "This file is too large to be a backup."),
        Ok(bytes) => {
            with_state(|s| s.pending_backup = Some(bytes));
            open_dialog(ui, Dialog::Restore);
        }
        Err(e) => report(ui, true, format!("Could not read the file: {e}")),
    }
}

fn restore_password(ui: &AppWindow, password: Zeroizing<String>) {
    let Some(bytes) = with_state(|s| s.pending_backup.clone()) else {
        return;
    };
    set_busy(ui, "Decrypting backup…");
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let result = backup::open(&bytes, &password);
        let _ = weak.upgrade_in_event_loop(move |ui| {
            app(&ui).set_busy(false);
            match result {
                Ok(contents) => {
                    with_state(|s| s.pending_backup = None);
                    let invalid = contents.invalid;
                    if contents.accounts.is_empty() && contents.logins.is_empty() && invalid == 0 {
                        return report(&ui, true, "The backup is empty.");
                    }
                    let text = with_state(|s| {
                        let vault = s.vault.as_mut()?;
                        let (accounts_before, logins_before) = (vault.entries.len(), vault.logins.len());
                        let result =
                            merge::merge(&mut vault.entries, &mut vault.logins, contents.accounts, contents.logins);
                        let new_accounts = vault.entries.len() - accounts_before;
                        let new_logins = vault.logins.len() - logins_before;
                        for _ in 0..new_accounts {
                            let id = next_id(s);
                            s.code_ids.push(id);
                        }
                        for _ in 0..new_logins {
                            let id = next_id(s);
                            s.login_ids.push(id);
                        }
                        if !save(&ui, s) {
                            return None;
                        }
                        refresh_all(&ui, s);
                        let mut text = result.summary();
                        if invalid > 0 {
                            text.push_str(&format!(" {} could not be read.", plural(invalid, "entry")));
                        }
                        Some(text)
                    });
                    if let Some(text) = text {
                        close_dialog(&ui);
                        toast(&ui, invalid > 0, text);
                    }
                }
                Err(crypto::EnvelopeError::WrongPassword) => report(&ui, true, "Wrong password for this backup."),
                Err(e) => report(&ui, true, e.to_string()),
            }
        });
    });
}

pub fn wire(ui: &AppWindow) {
    callback!(ui, on_open_export, |ui| require_pin(&ui, Pending::Export));
    callback!(ui, on_show_code_qr, |ui, id| require_pin(&ui, Pending::CodeQr(id)));
    callback!(ui, on_pin_entered, |ui, pin| pin_entered(&ui, Zeroizing::new(pin.to_string())));

    callback!(ui, on_toggle_pick, |ui, codes, index| with_state(|s| {
        let model = if codes { &s.export_codes } else { &s.export_logins };
        if let Some(mut row) = model.row_data(index.max(0) as usize) {
            row.checked = !row.checked;
            model.set_row_data(index as usize, row);
        }
        update_counts(&ui, s);
    }));

    callback!(ui, on_pick_all, |ui, codes, value| with_state(|s| {
        let model = if codes { &s.export_codes } else { &s.export_logins };
        for i in 0..model.row_count() {
            if let Some(mut row) = model.row_data(i) {
                if row.checked != value {
                    row.checked = value;
                    model.set_row_data(i, row);
                }
            }
        }
        update_counts(&ui, s);
    }));

    callback!(ui, on_export_qr, |ui| export_qr(&ui));

    callback!(ui, on_export_backup, |ui, password, confirm| {
        export_backup(&ui, Zeroizing::new(password.to_string()), &confirm)
    });

    callback!(ui, on_copy_secret, |ui, id| with_state(|s| {
        let Some(index) = s.code_ids.iter().position(|&x| x == id) else {
            return;
        };
        let Some(vault) = s.vault.as_ref() else {
            return;
        };
        let key = Zeroizing::new(vault.entries[index].secret.to_base32());
        copy_secret(&ui, s, key, "Setup key");
    }));

    callback!(ui, on_restore_backup, |ui| restore_backup(&ui));
    callback!(ui, on_restore_password, |ui, password| restore_password(&ui, Zeroizing::new(password.to_string())));
}
