//! Showing, hiding and closing the window, and the notification-area icon.

use std::time::Duration;

use authenticator::platform;
use authenticator::tray::{self, TrayEvent};
use slint::{CloseRequestResponse, ComponentHandle, Timer};

use super::*;

/// Starts the notification-area icon. Returns false where there is none.
pub fn start_tray(ui: &AppWindow) -> bool {
    let weak = ui.as_weak();
    let started = tray::start(move |event| {
        let weak = weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                on_tray(&ui, event);
            }
        });
    });
    if started {
        tray::set_locked(true);
    }
    started
}

fn on_tray(ui: &AppWindow, event: TrayEvent) {
    match event {
        TrayEvent::Open => show(ui),
        TrayEvent::Lock => with_state(|s| session::lock_now(ui, s)),
        TrayEvent::Quit => quit(),
        TrayEvent::SessionLocked | TrayEvent::Suspend => with_state(|s| {
            if s.vault.as_ref().is_some_and(|v| v.settings.lock_on_session_lock) {
                session::lock_now(ui, s);
            }
        }),
    }
}

/// Shows the window (from the tray, a second start of the app, or the browser).
pub fn show(ui: &AppWindow) {
    let _ = ui.show();
    ui.window().set_minimized(false);
    with_state(|s| {
        s.window_visible = true;
        // The native window may have been recreated; the timer picks it up again.
        s.hwnd = 0;
    });
    let weak = ui.as_weak();
    Timer::single_shot(Duration::from_millis(60), move || {
        let Some(ui) = weak.upgrade() else { return };
        let hwnd = native_handle(&ui);
        try_with_state(|s| {
            s.hwnd = hwnd;
            let hide = s.vault.as_ref().map(|v| v.settings.hide_from_capture).unwrap_or(true);
            platform::set_capture_protection(hwnd, hide);
        });
        platform::bring_to_front(hwnd);
        if app(&ui).get_page() == Page::Lock {
            ui.invoke_focus_pin();
        }
    });
}

/// Hides the window to the notification area (or minimizes it without one).
pub fn hide(ui: &AppWindow) {
    let tray = with_state(|s| s.tray);
    if !tray {
        ui.window().set_minimized(true);
        return;
    }
    let _ = ui.hide();
    with_state(|s| {
        s.window_visible = false;
        if !s.prefs.tray_hint_shown {
            s.prefs.tray_hint_shown = true;
            let _ = s.prefs.save();
            tray::notify(
                "Authenticator is still running",
                "Click the icon here to open it. To quit, right-click it and choose Quit.",
            );
        }
    });
}

pub fn quit() {
    tray::stop();
    let _ = slint::quit_event_loop();
}

pub fn wire(ui: &AppWindow) {
    let weak = ui.as_weak();
    ui.window().on_close_requested(move || {
        let Some(ui) = weak.upgrade() else { return CloseRequestResponse::HideWindow };
        let to_tray = with_state(|s| s.tray && s.prefs.close_to_tray);
        if to_tray {
            hide(&ui);
        } else {
            quit();
        }
        CloseRequestResponse::HideWindow
    });

    callback!(ui, on_quit, |_ui| quit());
    callback!(ui, on_hide_window, |ui| hide(&ui));
}
