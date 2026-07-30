// SPEC-004 CON-301 — the Android side of the root record's box.
//
// The blob this class is handed is already sealed under an Argon2id key derived
// from the user's passcode. What happens here is the second layer of ADR-302:
// encrypt that sealed blob under an AES-256-GCM key that lives in the Android
// Keystore and never leaves it, and write the result to app-private storage.
//
// Nothing in this file ever sees an unsealed seed. The blob is opaque.

package io.anuna.selfsame.store

import android.app.Activity
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class StoreArgs {
    lateinit var blob: String
}

/**
 * The commands are `storeRecord` / `loadRecord` / `deleteRecord`, not
 * `store` / `load` / `delete`. `Plugin` already defines `load(WebView)`, so a
 * command called `load` would be a same-name overload on a class whose commands
 * are indexed by reflection over method names. The Rust API in `src/lib.rs`
 * keeps CON-301's names; only the wire names differ, and they differ so that
 * this class has exactly one method called `load`.
 */
@TauriPlugin
class SecureStorePlugin(private val activity: Activity) : Plugin(activity) {

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        /** CON-301 fixes this alias. Changing it orphans every existing record. */
        private const val KEY_ALIAS = "io.anuna.selfsame.root"

        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        private const val GCM_TAG_BITS = 128
        private const val IV_BYTES = 12
        private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8

        private const val RECORD_VERSION: Byte = 1
        private const val FILE_NAME = "root-v1.bin"

        /**
         * The shortest byte string that could be a valid record: the version
         * byte, the IV, a GCM tag, and at least one byte of ciphertext.
         */
        private const val MIN_RECORD_BYTES = 1 + IV_BYTES + GCM_TAG_BYTES + 1

        private const val CODE_UNAVAILABLE = "storeUnavailable"
    }

    /**
     * Overwrite the stored record.
     *
     * The IV is **not** ours to choose: an AndroidKeyStore AES/GCM key is
     * generated with `setRandomizedEncryptionRequired(true)` by default, and
     * supplying an IV to `Cipher.init` for encryption under such a key throws.
     * The platform generates a fresh one per `init`, which is exactly the
     * "fresh per store" property CON-301 asks for — enforced rather than
     * remembered.
     */
    @Command
    fun storeRecord(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(StoreArgs::class.java)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, keyForEncryption())
            val ciphertext = cipher.doFinal(args.blob.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv

            if (iv == null || iv.size != IV_BYTES) {
                // Refuse rather than write a record whose header lies about its
                // own layout: a wrong IV length here would be discovered on the
                // next launch as an unreadable identity.
                invoke.reject(
                    "the Keystore produced a ${iv?.size ?: 0}-byte IV, expected $IV_BYTES",
                    CODE_UNAVAILABLE
                )
                return
            }

            val record = ByteArray(1 + IV_BYTES + ciphertext.size)
            record[0] = RECORD_VERSION
            System.arraycopy(iv, 0, record, 1, IV_BYTES)
            System.arraycopy(ciphertext, 0, record, 1 + IV_BYTES, ciphertext.size)

            writeAtomically(record)
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "could not write to the secure store", CODE_UNAVAILABLE)
        }
    }

    /**
     * Read the stored record.
     *
     * Resolves with a tagged object rather than rejecting, because the three
     * outcomes are not all errors and CON-301 turns on telling them apart:
     *
     *   { "state": "absent"  }                — nothing has ever been stored
     *   { "state": "present", "blob": "…" }   — the sealed record
     *   { "state": "corrupt", "detail": "…" } — a record is there and unreadable
     *
     * The third MUST NOT be reported as the first. A user whose store is damaged
     * and is told they have no identity will create a second one over the top of
     * the first, and the first is the one their contacts have already accepted.
     */
    @Command
    fun loadRecord(invoke: Invoke) {
        try {
            val file = recordFile()
            if (!file.exists()) {
                invoke.resolve(state("absent"))
                return
            }

            val raw = file.readBytes()

            // Full recognition before any semantic action (LangSec, PROTO-001
            // Principle 14). The record language is fixed-width and regular:
            //
            //   record  = %x01 iv ciphertext
            //   iv      = 12 OCTET
            //   ciphertext = 17*OCTET       ; >= 1 byte payload + 16-byte tag
            //
            // Anything outside it is corrupt, not absent, and no Cipher is
            // touched until the header has been accepted.
            if (raw.size < MIN_RECORD_BYTES) {
                invoke.resolve(corrupt("record is ${raw.size} bytes, shorter than any valid record"))
                return
            }
            if (raw[0] != RECORD_VERSION) {
                invoke.resolve(corrupt("record version ${raw[0].toInt()} is not recognised"))
                return
            }

            val key = existingKey()
            if (key == null) {
                // The record outlived its key. Reachable if app data were
                // restored onto a device whose Keystore never held the key —
                // which `noBackupFilesDir` is meant to prevent — or if the
                // Keystore entry were cleared independently.
                invoke.resolve(corrupt("the Keystore key for this record is no longer present"))
                return
            }

            val plaintext = try {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    GCMParameterSpec(GCM_TAG_BITS, raw, 1, IV_BYTES)
                )
                cipher.doFinal(raw, 1 + IV_BYTES, raw.size - 1 - IV_BYTES)
            } catch (e: GeneralSecurityException) {
                // A failed GCM tag means the ciphertext was altered or truncated.
                invoke.resolve(corrupt(e.message ?: "the record did not authenticate"))
                return
            }

            invoke.resolve(present(String(plaintext, Charsets.UTF_8)))
        } catch (e: Exception) {
            // An I/O failure says nothing about whether a record exists, so it
            // is an error and not an "absent" — the caller must not conclude
            // there is no identity.
            invoke.reject(e.message ?: "could not read the secure store", CODE_UNAVAILABLE)
        }
    }

    /**
     * Remove the record and the key that wrapped it. Idempotent: deleting
     * nothing succeeds, which is what `Custody::forget` relies on.
     *
     * The Keystore entry goes too. Leaving it would keep a key alive that can
     * decrypt nothing, and the next `storeRecord` would silently reuse it for a
     * new identity rather than generating a fresh one.
     */
    @Command
    fun deleteRecord(invoke: Invoke) {
        try {
            val file = recordFile()
            if (file.exists() && !file.delete()) {
                invoke.reject("could not delete the stored record", CODE_UNAVAILABLE)
                return
            }
            val keystore = keystore()
            if (keystore.containsAlias(KEY_ALIAS)) {
                keystore.deleteEntry(KEY_ALIAS)
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "could not clear the secure store", CODE_UNAVAILABLE)
        }
    }

    // ── storage ─────────────────────────────────────────────────────────────

    /**
     * `noBackupFilesDir`, not `filesDir` — REQ-303.
     *
     * Android's automatic backup would otherwise copy the ciphertext to the
     * user's Google account and restore it onto a replacement device, where the
     * Keystore key does not exist. The bytes would be useless, so REQ-303's
     * guarantee would hold; but the app would meet an undecryptable record and
     * correctly report a *corrupt* store to a user whose actual situation is a
     * new phone and a recovery phrase. Excluding the file from backup makes that
     * case read as "no identity here", which is both true and the state the
     * restore flow is built for.
     */
    private fun recordFile(): File = File(activity.noBackupFilesDir, FILE_NAME)

    /**
     * Write via a temporary file and rename.
     *
     * `storeRecord` overwrites — `Custody::confirm_backup` rewrites the record
     * of an identity that already exists. A crash midway through writing in
     * place would leave a truncated record, which is to say an identity
     * recoverable only from the twelve words. `rename(2)` replaces atomically,
     * so the previous record survives until the new one is complete.
     */
    private fun writeAtomically(bytes: ByteArray) {
        val destination = recordFile()
        val temporary = File(activity.noBackupFilesDir, "$FILE_NAME.new")
        temporary.writeBytes(bytes)
        if (!temporary.renameTo(destination)) {
            temporary.delete()
            throw java.io.IOException("could not replace the stored record")
        }
    }

    // ── the Keystore key ────────────────────────────────────────────────────

    private fun keystore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun existingKey(): SecretKey? = keystore().getKey(KEY_ALIAS, null) as? SecretKey

    private fun keyForEncryption(): SecretKey = existingKey() ?: generateKey()

    /**
     * Generate the AES-256-GCM key, hardware-backed where the device provides it
     * (REQ-302). It is generated inside the Keystore and never exported.
     *
     * **No `setUserAuthenticationRequired(true)`** — ADR-305, deferred by
     * decision and not by oversight. Adding it makes the OS demand a biometric
     * or device credential before this key will decrypt, which is REQ-024's
     * presence check enforced by the platform rather than by our passcode. It
     * also makes every root-key use a `BiometricPrompt` round-trip, invalidates
     * the key on biometric re-enrolment, and needs a fallback for devices with
     * nothing enrolled. That is a separate reviewable change; until it lands the
     * presence check is the Argon2id gate in `custody.rs`, as on desktop.
     */
    private fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_BITS)
                // Default, stated rather than assumed: it is what forbids us
                // supplying our own IV, and so what guarantees IV freshness.
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    // ── response shapes ─────────────────────────────────────────────────────

    // The three shapes `loadRecord` resolves with. They are the wire contract
    // with `LoadResponse` in src/lib.rs, and `tests/wire_contract.rs` checks
    // that both sides still agree — the one test of this plugin that runs
    // without an Android device.
    private fun state(value: String): JSObject = JSObject().apply { put("state", value) }

    private fun present(blob: String): JSObject =
        state("present").apply { put("blob", blob) }

    private fun corrupt(detail: String): JSObject =
        state("corrupt").apply { put("detail", detail) }
}
