//! The passwords list: rows, the editor, the generator and CSV import.

use authenticator::crypto::new_id;
use authenticator::login::{self, GeneratorOptions, Login, Password};
use authenticator::otp::{self, OtpKind};
use authenticator::vault::Vault;
use authenticator::{csv, merge, platform};
use slint::{Model, ModelRc, SharedString, VecModel};
use zeroize::Zeroizing;

use super::codes::{live, titles};
use super::session::next_id;
use super::*;

const MAX_CSV_FILE: u64 = 20 * 1024 * 1024;

fn sort_key(l: &Login) -> (String, String) {
    (l.display_title().to_lowercase(), l.username.to_lowercase())
}

fn site(l: &Login) -> String {
    let host = l.host();
    host.strip_prefix("www.").unwrap_or(&host).to_string()
}

/// Title, code, seconds left and "about to change" of the linked 2FA code.
fn linked_code(l: &Login, vault: &Vault, now: u64) -> (String, String, i32, bool) {
    if l.otp.is_empty() {
        return Default::default();
    }
    match vault.entries.iter().find(|a| a.id == l.otp) {
        Some(account) => {
            let (title, _) = titles(account);
            let (code, remaining, _, warn) = live(account, now);
            let remaining = if account.kind == OtpKind::Totp { remaining } else { 0 };
            (title, code, remaining, warn)
        }
        None => Default::default(),
    }
}

fn make_row(id: i32, l: &Login, vault: &Vault, now: u64) -> LoginRow {
    let title = l.display_title();
    let (otp_title, otp_code, otp_remaining, otp_warn) = linked_code(l, vault, now);
    LoginRow {
        id,
        initial: first_letter(&title),
        title: title.into(),
        username: l.username.as_str().into(),
        site: site(l).into(),
        url: l.url.as_str().into(),
        notes: l.notes.as_str().into(),
        modified: if l.modified > 0 { platform::local_date(l.modified).into() } else { SharedString::new() },
        otp_title: otp_title.into(),
        otp_code: otp_code.into(),
        otp_remaining,
        otp_warn,
    }
}

pub fn index_of(s: &State, id: i32) -> Option<usize> {
    s.login_ids.iter().position(|&x| x == id)
}

/// Rebuilds the list (sorted by title). `select` picks a row by id;
/// otherwise the selection is kept.
pub fn refresh(ui: &AppWindow, s: &mut State, select: Option<i32>) {
    let a = app(ui);
    let keep = select.or_else(|| selected_id(&s.login_rows, a.get_login_index(), |r: &LoginRow| r.id));
    let now = otp::now_unix();
    let filter = s.filter.trim().to_lowercase();
    let mut rows = Vec::new();
    s.visible_logins.clear();
    if let Some(vault) = s.vault.as_ref() {
        let mut order: Vec<usize> = (0..vault.logins.len())
            .filter(|&i| {
                let l = &vault.logins[i];
                filter.is_empty()
                    || l.display_title().to_lowercase().contains(&filter)
                    || l.username.to_lowercase().contains(&filter)
                    || l.url.to_lowercase().contains(&filter)
                    || l.notes.to_lowercase().contains(&filter)
            })
            .collect();
        order.sort_by_cached_key(|&i| sort_key(&vault.logins[i]));
        for i in order {
            s.visible_logins.push(i);
            rows.push(make_row(s.login_ids[i], &vault.logins[i], vault, now));
        }
    }
    let index = keep.and_then(|id| rows.iter().position(|r| r.id == id)).map(|i| i as i32).unwrap_or(-1);
    s.login_rows.set_vec(rows);
    a.set_login_index(index);
    a.set_login_total(s.vault.as_ref().map(|v| v.logins.len()).unwrap_or(0) as i32);
}

/// Called every second: the linked 2FA codes.
pub fn update_rows(s: &State, now: u64) {
    let Some(vault) = s.vault.as_ref() else {
        return;
    };
    for (row, &index) in s.visible_logins.iter().enumerate() {
        let Some(login) = vault.logins.get(index) else {
            continue;
        };
        if login.otp.is_empty() {
            continue;
        }
        let Some(mut data) = s.login_rows.row_data(row) else {
            continue;
        };
        let (_, code, remaining, warn) = linked_code(login, vault, now);
        if data.otp_code != code.as_str() || data.otp_remaining != remaining || data.otp_warn != warn {
            data.otp_code = code.into();
            data.otp_remaining = remaining;
            data.otp_warn = warn;
            s.login_rows.set_row_data(row, data);
        }
    }
}

// ------------------------------------------------------------------ editor

/// Empties the editor fields (they may hold a password).
pub fn clear_editor(ui: &AppWindow) {
    let a = app(ui);
    a.set_login_edit_id(-1);
    a.set_login_title("".into());
    a.set_login_username("".into());
    a.set_login_password("".into());
    a.set_login_url("".into());
    a.set_login_notes("".into());
    a.set_login_otp_index(0);
}

/// Fills the "2FA code" choices and returns the index of `linked`.
fn fill_otp_choices(ui: &AppWindow, s: &mut State, linked: &str) -> i32 {
    let Some(vault) = s.vault.as_ref() else {
        return 0;
    };
    let mut labels: Vec<SharedString> = vec!["None".into()];
    let mut ids = vec![String::new()];
    for account in &vault.entries {
        let (title, name) = titles(account);
        labels.push(if name.is_empty() { title.into() } else { format!("{title} ({name})").into() });
        ids.push(account.id.clone());
    }
    let index = ids.iter().position(|id| !linked.is_empty() && id == linked).unwrap_or(0) as i32;
    s.otp_choice_ids = ids;
    app(ui).set_otp_choices(ModelRc::new(VecModel::from(labels)));
    index
}

fn open_editor(ui: &AppWindow, id: i32, confirm_delete: bool) {
    let a = app(ui);
    let found = with_state(|s| {
        let index = if id >= 0 { Some(index_of(s, id)?) } else { None };
        let login = match index {
            Some(i) => s.vault.as_ref()?.logins[i].clone(),
            None => {
                s.vault.as_ref()?;
                Login::default()
            }
        };
        let otp_index = fill_otp_choices(ui, s, &login.otp);
        a.set_login_edit_id(id);
        a.set_login_title(login.title.as_str().into());
        a.set_login_username(login.username.as_str().into());
        a.set_login_password(login.password.as_str().into());
        a.set_login_url(login.url.as_str().into());
        a.set_login_notes(login.notes.as_str().into());
        a.set_login_otp_index(otp_index);
        Some(())
    });
    if found.is_some() {
        a.set_section(Section::Passwords);
        open_dialog(ui, Dialog::EditLogin);
        a.set_confirm_delete(confirm_delete);
    }
}

fn save_login(ui: &AppWindow) -> Result<(), String> {
    let a = app(ui);
    let id = a.get_login_edit_id();
    with_state(|s| {
        let otp = s.otp_choice_ids.get(a.get_login_otp_index().max(0) as usize).cloned().unwrap_or_default();
        let now = otp::now_unix() as i64;
        let index = if id >= 0 { Some(index_of(s, id).ok_or("This password no longer exists.")?) } else { None };
        let vault = s.vault.as_mut().ok_or("Locked")?;
        let mut login = match index {
            Some(i) => vault.logins[i].clone(),
            None => Login { id: new_id(), created: now, ..Default::default() },
        };
        login.title = a.get_login_title().trim().to_string();
        login.username = a.get_login_username().trim().to_string();
        login.password = Password::new(a.get_login_password().as_str());
        login.url = a.get_login_url().trim().to_string();
        login.notes = a.get_login_notes().trim_end().to_string();
        login.otp = otp;
        login.modified = now;
        login.validate().map_err(|e| {
            if e.contains("title or a website") { "Enter a title or a website.".to_string() } else { format!("{e}.") }
        })?;
        let ui_id = match index {
            Some(i) => {
                vault.logins[i] = login;
                s.login_ids[i]
            }
            None => {
                vault.logins.push(login);
                let new = next_id(s);
                s.login_ids.push(new);
                new
            }
        };
        if !save(ui, s) {
            return Err("Could not save.".into());
        }
        codes::refresh(ui, s, None);
        refresh(ui, s, Some(ui_id));
        Ok(())
    })
}

// ------------------------------------------------------------------ generator

fn generator_options(ui: &AppWindow) -> GeneratorOptions {
    let a = app(ui);
    GeneratorOptions {
        length: a.get_gen_length().clamp(login::GENERATOR_MIN_LEN as i32, login::GENERATOR_MAX_LEN as i32) as u32,
        lowercase: a.get_gen_lower(),
        uppercase: a.get_gen_upper(),
        digits: a.get_gen_digits(),
        symbols: a.get_gen_symbols(),
        avoid_similar: a.get_gen_similar(),
    }
}

/// Remembers the generator options (part of the encrypted settings).
fn store_generator(ui: &AppWindow, options: GeneratorOptions) {
    with_state(|s| {
        if let Some(vault) = s.vault.as_mut() {
            if vault.settings.generator != options {
                vault.settings.generator = options;
                save(ui, s);
            }
        }
    });
}

// ------------------------------------------------------------------ CSV

fn import_csv(ui: &AppWindow) {
    let Some(path) = dialogs::open_csv(ui) else {
        return;
    };
    let too_big = std::fs::metadata(&path).map(|m| m.len() > MAX_CSV_FILE).unwrap_or(false);
    if too_big {
        return report(ui, true, "This file is too large.");
    }
    let text = match std::fs::read(&path) {
        Ok(bytes) => Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) => return report(ui, true, format!("Could not read the file: {e}")),
    };
    let imported = match csv::import(&text) {
        Ok(imported) => imported,
        Err(e) => return report(ui, true, format!("{e}.")),
    };
    let skipped_rows = imported.skipped;
    let a = app(ui);
    with_state(|s| {
        let Some(vault) = s.vault.as_mut() else {
            return;
        };
        let (accounts_before, logins_before) = (vault.entries.len(), vault.logins.len());
        let result = merge::merge(&mut vault.entries, &mut vault.logins, imported.accounts, imported.logins);
        let (new_accounts, new_logins) = (vault.entries.len() - accounts_before, vault.logins.len() - logins_before);
        for _ in 0..new_accounts {
            let id = next_id(s);
            s.code_ids.push(id);
        }
        for _ in 0..new_logins {
            let id = next_id(s);
            s.login_ids.push(id);
        }
        if !save(ui, s) {
            return;
        }
        a.set_section(Section::Passwords);
        refresh_all(ui, s);
        let mut text = result.summary();
        if skipped_rows > 0 {
            text.push_str(&format!(" {} skipped.", plural(skipped_rows, "row")));
        }
        text.push_str(" Now delete the CSV file: it has your passwords in plain text.");
        toast(ui, false, text);
    });
}

pub fn wire(ui: &AppWindow) {
    callback!(ui, on_new_login, |ui| open_editor(&ui, -1, false));
    callback!(ui, on_edit_login, |ui, id| open_editor(&ui, id, false));
    callback!(ui, on_ask_delete_login, |ui, id| open_editor(&ui, id, true));

    callback!(ui, on_save_login, |ui| match save_login(&ui) {
        Ok(()) => {
            let new = app(&ui).get_login_edit_id() < 0;
            close_dialog(&ui);
            toast(&ui, false, if new { "Password saved." } else { "Changes saved." });
        }
        Err(e) => report(&ui, true, e),
    });

    callback!(ui, on_delete_login, |ui, id| {
        let deleted = with_state(|s| {
            let index = index_of(s, id)?;
            s.vault.as_mut()?.logins.remove(index);
            s.login_ids.remove(index);
            let ok = save(&ui, s);
            refresh_all(&ui, s);
            Some(ok)
        });
        close_dialog(&ui);
        if deleted == Some(true) {
            toast(&ui, false, "Password deleted.");
        }
    });

    callback!(ui, on_copy_username, |ui, id| with_state(|s| {
        let Some(index) = index_of(s, id) else { return };
        let Some(vault) = s.vault.as_ref() else {
            return;
        };
        let username = Zeroizing::new(vault.logins[index].username.clone());
        copy_secret(&ui, s, username, "Username");
    }));

    callback!(ui, on_copy_password, |ui, id| with_state(|s| {
        let Some(index) = index_of(s, id) else { return };
        let Some(vault) = s.vault.as_ref() else {
            return;
        };
        let password = Zeroizing::new(vault.logins[index].password.as_str().to_string());
        copy_secret(&ui, s, password, "Password");
    }));

    callback!(ui, on_copy_login_code, |ui, id| with_state(|s| {
        let Some(index) = index_of(s, id) else { return };
        let Some(vault) = s.vault.as_ref() else {
            return;
        };
        let link = &vault.logins[index].otp;
        let Some(account) = vault.entries.iter().find(|a| !link.is_empty() && &a.id == link) else {
            toast(&ui, true, "This password has no 2FA code. Choose one with Edit.");
            return;
        };
        let code = Zeroizing::new(account.code_at(otp::now_unix()));
        copy_secret(&ui, s, code, "2FA code");
    }));

    callback!(ui, on_open_url, |ui, id| {
        let url = with_state(|s| {
            let index = index_of(s, id)?;
            Some(s.vault.as_ref()?.logins[index].url.clone())
        });
        match url.as_deref().and_then(login::launch_url) {
            Some(url) => {
                if !platform::open_external(std::ffi::OsStr::new(&url)) {
                    toast(&ui, true, "Could not open the browser.");
                }
            }
            None => toast(&ui, true, "This password has no website address."),
        }
    });

    callback!(ui, on_reveal_password, |ui, id| {
        let password = with_state(|s| {
            let index = index_of(s, id)?;
            Some(s.vault.as_ref()?.logins[index].password.as_str().to_string())
        });
        if let Some(password) = password {
            let a = app(&ui);
            a.set_revealed_password(if password.is_empty() { "(empty)".into() } else { password.into() });
            a.set_revealed_id(id);
        }
    });

    callback!(ui, on_fill_generated, |ui| {
        let options = generator_options(&ui);
        let password = login::generate_password(&options);
        app(&ui).set_login_password(password.as_str().into());
        store_generator(&ui, options);
    });

    callback!(ui, on_generator_changed, |ui| {
        let options = generator_options(&ui);
        app(&ui).set_gen_result(login::generate_password(&options).as_str().into());
        store_generator(&ui, options);
    });

    callback!(ui, on_copy_generated, |ui| {
        let text = Zeroizing::new(app(&ui).get_gen_result().to_string());
        with_state(|s| copy_secret(&ui, s, text, "Password"));
    });

    callback!(ui, on_import_csv, |ui| import_csv(&ui));
}
