// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;

fn main() -> Result<(), slint::PlatformError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Started with Windows: stay in the notification area until needed.
    let start_hidden = args.iter().any(|a| a == "--tray");
    if !authenticator::platform::acquire_single_instance(gui::WINDOW_TITLE, !start_hidden) {
        return Ok(());
    }
    gui::run(start_hidden)
}
