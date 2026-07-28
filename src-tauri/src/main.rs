// Selfsame. The Windows subsystem attribute keeps a console window from
// appearing behind the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    selfsame_lib::run()
}
