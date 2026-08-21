#!/usr/bin/env bash
# Stamp `android:allowBackup="false"` (and the API 31+ data-extraction rules)
# into the GENERATED Android manifest. Run after `cargo tauri android init`
# and before any build; running it twice is a no-op.
#
# Why this exists: the root record is sealed under a non-exportable
# AndroidKeyStore key (StorePlugin.kt) that is destroyed with the install.
# Android's default (allowBackup=true) backs up the app's SharedPreferences
# and restores them on reinstall — an encrypted blob whose key no longer
# exists anywhere. The app then correctly refuses to conflate "undecryptable"
# with "absent" and every reinstall greets the user with "The stored identity
# record could not be decrypted". Backup of device-bound ciphertext can never
# restore a working identity; the recovery phrase is the restore path.
#
# It patches gen/ (which ADR-204 keeps uncommitted) rather than a checked-in
# manifest, so it must be invoked by both CI (android.yml) and any local
# Android build. Portable across BSD/GNU userlands: awk, no sed -i.
set -euo pipefail
cd "$(dirname "$0")"

manifest=gen/android/app/src/main/AndroidManifest.xml
[ -f "$manifest" ] || {
  echo "no generated manifest at src-tauri/$manifest — run 'cargo tauri android init' first" >&2
  exit 1
}

if grep -q 'android:allowBackup' "$manifest"; then
  echo "backup already disabled in src-tauri/$manifest"
else
  awk '
    { print }
    !done && /<application$/ {
      print "        android:allowBackup=\"false\""
      print "        android:fullBackupContent=\"false\""
      print "        android:dataExtractionRules=\"@xml/data_extraction_rules\""
      done = 1
    }
  ' "$manifest" > "$manifest.tmp"
  grep -q 'android:allowBackup="false"' "$manifest.tmp" || {
    echo "patch did not apply — the generated <application> tag no longer matches" >&2
    rm -f "$manifest.tmp"
    exit 1
  }
  mv "$manifest.tmp" "$manifest"
  echo "backup disabled in src-tauri/$manifest"
fi

# API 31+ reads these instead of fullBackupContent. Everything is excluded:
# there is no partial state worth carrying — a store without its wrapping key
# is garbage, and everything else is re-derivable from the identity.
rules=gen/android/app/src/main/res/xml/data_extraction_rules.xml
mkdir -p "$(dirname "$rules")"
cat > "$rules" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- Written by patch-android-backup.sh — do not edit; the source of truth is
     that script. Nothing leaves the device: the root record is wrapped by a
     non-exportable keystore key, so a restored copy is undecryptable by
     construction. -->
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="root" path="." />
    <exclude domain="file" path="." />
    <exclude domain="database" path="." />
    <exclude domain="sharedpref" path="." />
    <exclude domain="external" path="." />
  </cloud-backup>
  <device-transfer>
    <exclude domain="root" path="." />
    <exclude domain="file" path="." />
    <exclude domain="database" path="." />
    <exclude domain="sharedpref" path="." />
    <exclude domain="external" path="." />
  </device-transfer>
</data-extraction-rules>
EOF
echo "data extraction rules written to src-tauri/$rules"
