fn main() {
    // The short commit sha, surfaced on the home screen via the `build_info`
    // command. An installed APK carries no other visible mark of what it was
    // built from — `version` has sat at 0.1.0 across every dev build — so
    // without this, "which build is this phone actually running" is a
    // debugging session instead of a glance.
    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|sha| sha.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SELFSAME_BUILD_SHA={sha}");
    // Re-stamp when HEAD moves, not only when this file changes. In a
    // worktree .git is a file, which rerun-if-changed handles the same way.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    tauri_build::build()
}
