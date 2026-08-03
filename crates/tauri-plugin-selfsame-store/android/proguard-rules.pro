# The Tauri plugin bridge dispatches to @Command methods reflectively, and
# parses @InvokeArg classes by field name. Both are invisible to the shrinker,
# so both are kept explicitly rather than relying on the consumer rules of
# whichever tauri-android revision happens to be vendored in.
-keep class io.anuna.selfsame.store.** { *; }
-keepclassmembers class io.anuna.selfsame.store.** { *; }
