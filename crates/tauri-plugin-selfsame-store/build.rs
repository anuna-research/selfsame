// The root record is not a webview-reachable resource.
//
// A Tauri plugin normally lists the commands it exposes to the frontend, and
// the capability system then decides which windows may call them. This plugin
// lists **none**: `Custody` is the only caller, it is Rust, and it reaches the
// plugin through `run_mobile_plugin` rather than through the invoke bridge.
//
// The empty list is therefore a security property rather than an omission —
// there is no permission a capability file could grant that would let JavaScript
// read or write the sealed root, because no such command is generated.
const COMMANDS: &[&str] = &[];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
