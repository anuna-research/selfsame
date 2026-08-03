# Applied to the consuming application. Same reasoning as proguard-rules.pro:
# the plugin's classes are only ever reached reflectively from the Tauri bridge.
-keep class io.anuna.selfsame.store.** { *; }
-keepclassmembers class io.anuna.selfsame.store.** { *; }
