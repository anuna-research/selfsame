// SPEC-004 CON-301.
//
// `COMMANDS` is deliberately **empty**, and that is the security property, not
// an omission. `tauri_plugin::Builder` autogenerates an `allow-$command`
// permission for every name listed here and thereby makes it callable from the
// webview over IPC. This plugin reads and writes the sealed root record: a
// webview-reachable `load` would hand the record to any script running in the
// app, and a webview-reachable `delete` would let one destroy the identity.
//
// The Kotlin side is reached only through `PluginHandle::run_mobile_plugin`
// from Rust (`src/lib.rs`), which does not pass through the ACL at all. So the
// commands exist on the Kotlin class, and no capability can name them.
const COMMANDS: &[&str] = &[];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
