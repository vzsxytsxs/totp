//! Creating the vault, unlocking, locking, search and settings.

use std::time::{Duration, Instant};

use authenticator::platform;
use authenticator::vault::{self, Vault, VaultError};
use slint::{ComponentHandle, ModelRc};
use zeroize::Zeroizing;

use super::*;

/// Wrong PINs allowed before the app starts imposing a waiting time.
const FREE_ATTEMPTS: u32 = 5;

/// Seconds to wait before the next PIN attempt, if any.
pub fn pin_wait(s: &State) -> Option<u64> {
    s.locked_until.and_then(|t| t.checked_duration_since(Instant::now())).map(|d| d.as_secs() + 1)
}

/// Counts a wrong PIN and returns the message to show.
pub fn wrong_pin(s: &mut State) -> String {
    s.failed_attempts += 1;
    if s.failed_attempts >= FREE_ATTEMPTS {
        let secs = 30u64 << (s.failed_attempts - FREE_ATTEMPTS).min(5);
        s.locked_until = Some(Instant::now() + Duration::from_secs(secs));
        format!("Wrong PIN. Too many attempts: wait {secs} s.")
    } else {
        "Wrong PIN.".to_string()
    }
}

pub fn lock_now(ui: &AppWindow, s: &mut State) {
    let a = app(ui);
    clear_clipboard_if_ours(s);
    s.vault = None;
    s.code_ids.clear();
    s.login_ids.clear();
    s.filter.clear();
    s.pending = None;
    s.pending_backup = None;
    s.confirmed_until = None;
    s.otp_choice_ids.clear();
    s.export_codes.set_vec(Vec::new());
    s.export_logins.set_vec(Vec::new());
    refresh_all(ui, s);
    a.set_search("".into());
    a.set_revealed_id(-1);
    a.set_revealed_password("".into());
    a.set_gen_result("".into());
    a.set_qr_images(ModelRc::default());
    logins::clear_editor(ui);
    a.set_confirm_delete(false);
    a.set_dialog(Dialog::None);
    a.set_lock_error("".into());
    a.set_page(Page::Lock);
    authenticator::tray::set_locked(true);
    ui.invoke_focus_pin();
}

pub fn open_vault(ui: &AppWindow, s: &mut State, vault: Vault) {
    let a = app(ui);
    s.code_ids = (0..vault.entries.len()).map(|_| next_id(s)).collect();
    s.login_ids = (0..vault.logins.len()).map(|_| next_id(s)).collect();
    let settings = &vault.settings;
    platform::set_capture_protection(s.hwnd, settings.hide_from_capture);
    let g = settings.generator;
    a.set_gen_length(g.length as i32);
    a.set_gen_lower(g.lowercase);
    a.set_gen_upper(g.uppercase);
    a.set_gen_digits(g.digits);
    a.set_gen_symbols(g.symbols);
    a.set_gen_similar(g.avoid_similar);
    a.set_status_right(auto_lock_text(settings.auto_lock_minutes).into());
    s.vault = Some(vault);
    s.filter.clear();
    s.last_activity = Instant::now();
    a.set_search("".into());
    a.set_code_index(-1);
    a.set_login_index(-1);
    refresh_all(ui, s);
    a.set_lock_error("".into());
    a.set_page(Page::Main);
    authenticator::tray::set_locked(false);
    ui.invoke_focus_list();
}

pub fn next_id(s: &mut State) -> i32 {
    s.next_id += 1;
    s.next_id
}

fn auto_lock_text(minutes: u32) -> String {
    match minutes {
        0 => "Auto-lock off".into(),
        60 => "Locks after 1 hour without use".into(),
        m => format!("Locks after {m} min without use"),
    }
}

fn open_settings(ui: &AppWindow) {
    let a = app(ui);
    let ok = with_state(|s| {
        let Some(vault) = s.vault.as_ref() else {
            return false;
        };
        let settings = &vault.settings;
        a.set_auto_lock_index(
            AUTO_LOCK_MINUTES.iter().position(|&m| m == settings.auto_lock_minutes).unwrap_or(1) as i32
        );
        a.set_clipboard_index(
            CLIPBOARD_SECONDS.iter().position(|&m| m == settings.clipboard_clear_seconds).unwrap_or(1) as i32,
        );
        a.set_hide_from_capture(settings.hide_from_capture);
        a.set_lock_on_session_lock(settings.lock_on_session_lock);
        a.set_confirm_browser_access(settings.confirm_browser_access);
        a.set_close_to_tray(s.prefs.close_to_tray);
        a.set_start_with_windows(platform::autostart_enabled());
        true
    });
    if ok {
        open_dialog(ui, Dialog::Settings);
    }
}

pub fn wire(ui: &AppWindow) {
    callback!(ui, on_create_pin, |ui, pin, confirm| {
        let a = app(&ui);
        let pin = Zeroizing::new(pin.to_string());
        if pin.chars().count() < vault::MIN_PIN_LEN {
            a.set_lock_error(format!("Use at least {} characters.", vault::MIN_PIN_LEN).into());
            return;
        }
        if *pin != confirm.as_str() {
            a.set_lock_error("The two entries do not match.".into());
            return;
        }
        let path = with_state(|s| s.vault_path.clone());
        set_busy(&ui, "Creating secure storage…");
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let result = Vault::create(&path, &pin);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                app(&ui).set_busy(false);
                match result {
                    Ok(vault) => with_state(|s| open_vault(&ui, s, vault)),
                    Err(e) => app(&ui).set_lock_error(e.to_string().into()),
                }
            });
        });
    });

    callback!(ui, on_unlock, |ui, pin| {
        let a = app(&ui);
        let pin = Zeroizing::new(pin.to_string());
        if pin.is_empty() {
            return;
        }
        if let Some(wait) = with_state(|s| pin_wait(s)) {
            a.set_lock_error(format!("Too many wrong attempts. Try again in {wait} s.").into());
            return;
        }
        let path = with_state(|s| s.vault_path.clone());
        set_busy(&ui, "Unlocking…");
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let result = Vault::unlock(&path, &pin);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                let a = app(&ui);
                a.set_busy(false);
                with_state(|s| match result {
                    Ok(vault) => {
                        s.failed_attempts = 0;
                        s.locked_until = None;
                        open_vault(&ui, s, vault);
                    }
                    Err(VaultError::WrongPin) => a.set_lock_error(wrong_pin(s).into()),
                    Err(e) => a.set_lock_error(e.to_string().into()),
                });
            });
        });
    });

    callback!(ui, on_reset_all, |ui, confirm| {
        if confirm != "DELETE" {
            return;
        }
        let a = app(&ui);
        with_state(|s| match vault::destroy(&s.vault_path) {
            Ok(()) => {
                s.failed_attempts = 0;
                s.locked_until = None;
                a.set_lock_error("".into());
                a.set_page(Page::Setup);
            }
            Err(e) => a.set_lock_error(format!("Could not delete the data: {e}").into()),
        });
    });

    callback!(ui, on_lock, |ui| with_state(|s| lock_now(&ui, s)));

    callback!(ui, on_search_changed, |ui, text| {
        with_state(|s| {
            s.filter = text.to_string();
            refresh_all(&ui, s);
        });
    });

    callback!(ui, on_section_changed, |ui| {
        app(&ui).set_revealed_id(-1);
        app(&ui).set_revealed_password("".into());
        ui.invoke_focus_list();
    });

    callback!(ui, on_selection_changed, |ui| {
        app(&ui).set_revealed_id(-1);
        app(&ui).set_revealed_password("".into());
    });

    callback!(ui, on_close_dialog, |ui| close_dialog(&ui));

    callback!(ui, on_open_settings, |ui| open_settings(&ui));

    callback!(ui, on_settings_changed, |ui| {
        let a = app(&ui);
        with_state(|s| {
            let Some(vault) = s.vault.as_mut() else {
                return;
            };
            let settings = &mut vault.settings;
            settings.auto_lock_minutes =
                AUTO_LOCK_MINUTES[(a.get_auto_lock_index().max(0) as usize).min(AUTO_LOCK_MINUTES.len() - 1)];
            settings.clipboard_clear_seconds =
                CLIPBOARD_SECONDS[(a.get_clipboard_index().max(0) as usize).min(CLIPBOARD_SECONDS.len() - 1)];
            settings.hide_from_capture = a.get_hide_from_capture();
            settings.lock_on_session_lock = a.get_lock_on_session_lock();
            settings.confirm_browser_access = a.get_confirm_browser_access();
            platform::set_capture_protection(s.hwnd, settings.hide_from_capture);
            a.set_status_right(auto_lock_text(settings.auto_lock_minutes).into());
            s.prefs.close_to_tray = a.get_close_to_tray();
            save_prefs(&ui, s);
            if save(&ui, s) {
                report(&ui, false, "Settings saved.");
            }
        });
    });

    callback!(ui, on_start_with_windows_changed, |ui, enabled| {
        match platform::set_autostart(enabled) {
            Ok(()) => report(
                &ui,
                false,
                if enabled {
                    "Authenticator will start with Windows, locked, in the notification area."
                } else {
                    "Authenticator will no longer start with Windows."
                },
            ),
            Err(e) => {
                app(&ui).set_start_with_windows(platform::autostart_enabled());
                report(&ui, true, format!("Could not change this: {e}"));
            }
        }
    });

    callback!(ui, on_change_pin, |ui, current, new_pin, confirm| {
        let current = Zeroizing::new(current.to_string());
        let new_pin = Zeroizing::new(new_pin.to_string());
        if new_pin.chars().count() < vault::MIN_PIN_LEN {
            return report(&ui, true, format!("Use at least {} characters.", vault::MIN_PIN_LEN));
        }
        if *new_pin != confirm.as_str() {
            return report(&ui, true, "The new PIN entries do not match.");
        }
        if let Some(wait) = with_state(|s| pin_wait(s)) {
            return report(&ui, true, format!("Too many wrong attempts. Try again in {wait} s."));
        }
        let Some(mut vault) = with_state(|s| s.vault.take()) else {
            return;
        };
        set_busy(&ui, "Changing PIN…");
        let weak = ui.as_weak();
        std::thread::spawn(move || {
            let result = if vault.verify_pin(&current) {
                vault.change_pin(&new_pin).map_err(|e| e.to_string())
            } else {
                Err(String::new())
            };
            let _ = weak.upgrade_in_event_loop(move |ui| {
                app(&ui).set_busy(false);
                with_state(|s| {
                    s.vault = Some(vault);
                    match result {
                        Ok(()) => {
                            s.failed_attempts = 0;
                            report(&ui, false, "PIN changed.");
                        }
                        Err(e) if e.is_empty() => {
                            let message = wrong_pin(s).replace("Wrong PIN", "The current PIN is wrong");
                            report(&ui, true, message);
                        }
                        Err(e) => report(&ui, true, e),
                    }
                });
            });
        });
    });
}
