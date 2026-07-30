# Tauri dispatches to `@Command` methods by reflection, so a minifying build
# that renamed or removed them would compile cleanly and then fail at runtime
# with a command that cannot be found — on the one code path that persists the
# root key. The app currently ships debug-signed with minification off
# (SPEC-003 ADR-201), so this rule is not load-bearing today; it is here so that
# turning minification on for a release build cannot quietly break storage.
-keep class io.anuna.selfsame.store.SecureStorePlugin { *; }
-keepattributes *Annotation*
