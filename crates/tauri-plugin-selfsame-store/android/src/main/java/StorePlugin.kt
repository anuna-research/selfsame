package io.anuna.selfsame.store

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Keystore-backed storage for the Selfsame root record.
 *
 * `keyring` 3 has no Android backend and falls through to its testing mock, so
 * on Android every `set_password` was accepted and discarded and the app could
 * never create an identity. This is the store that actually persists.
 *
 * The value arriving here is already sealed by the Rust side under an Argon2id
 * key derived from the user's passcode. What this class adds is the second
 * layer SPEC-001 REQ-024 asks for: a non-exportable AES-256-GCM key held in the
 * TEE (StrongBox where the device has it), so the ciphertext is useless off the
 * device even to someone who has extracted it.
 *
 * There are no permissions and no exported components — see AndroidManifest.xml.
 */
@TauriPlugin
class StorePlugin(private val activity: Activity) : Plugin(activity) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "io.anuna.selfsame.root-wrapping-key"
        private const val PREFS = "io.anuna.selfsame.store"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"

        /** GCM authentication tag length, in bits. */
        private const val TAG_BITS = 128

        /** Leading byte of a stored blob, so the format can change later. */
        private const val FORMAT_V1: Byte = 1
    }

    private val prefs: SharedPreferences by lazy {
        activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    @InvokeArg
    class KeyArgs {
        lateinit var key: String
    }

    @InvokeArg
    class SetArgs {
        lateinit var key: String
        lateinit var value: String
    }

    /**
     * Read a record.
     *
     * Resolves with `value` absent when this device has never stored one, and
     * **rejects** when a record exists but will not decrypt. Those two cases
     * must not be conflated: reporting an undecryptable record as "absent" is
     * what would send the user back to the first-run screen and silently
     * abandon an identity that is still there.
     */
    @Command
    fun get(invoke: Invoke) {
        val args = invoke.parseArgs(KeyArgs::class.java)
        val stored = prefs.getString(args.key, null)

        if (stored == null) {
            invoke.resolve(JSObject())
            return
        }

        try {
            invoke.resolve(JSObject().put("value", decrypt(stored)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            // The wrapping key is gone — typically the device credential was
            // removed, or biometrics were re-enrolled. The record is
            // unrecoverable on this device and the recovery phrase is the only
            // way back, so say that rather than pretending it never existed.
            invoke.reject(
                "The device keystore key for this identity was invalidated, so the " +
                    "stored record can no longer be opened. Restore from your " +
                    "recovery phrase.",
                "keyInvalidated",
                e,
            )
        } catch (e: Exception) {
            invoke.reject(
                "The stored identity record could not be decrypted: ${e.message}",
                "decryptFailed",
                e,
            )
        }
    }

    /**
     * Store a record, replacing any previous value under the same key.
     *
     * Uses `commit()` rather than `apply()`. `apply()` returns before the write
     * reaches disk, which would let this resolve successfully for a write that
     * has not durably happened — a quieter version of the defect this plugin
     * exists to fix. The boolean result is checked for the same reason.
     */
    @Command
    fun set(invoke: Invoke) {
        val args = invoke.parseArgs(SetArgs::class.java)
        try {
            val blob = encrypt(args.value)
            if (!prefs.edit().putString(args.key, blob).commit()) {
                invoke.reject(
                    "The identity record could not be written to storage.",
                    "writeFailed",
                )
                return
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(
                "The identity record could not be encrypted: ${e.message}",
                "encryptFailed",
                e,
            )
        }
    }

    /**
     * Remove a record, and the wrapping key with it.
     *
     * Deleting the key matters: the record is what the seal protects, and
     * leaving a live TEE key behind for a deleted identity is state nobody
     * asked to keep. Succeeds whether or not a record was present.
     */
    @Command
    fun delete(invoke: Invoke) {
        val args = invoke.parseArgs(KeyArgs::class.java)
        try {
            prefs.edit().remove(args.key).commit()
            if (prefs.all.isEmpty()) {
                keystore().deleteEntry(KEY_ALIAS)
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(
                "The identity record could not be removed: ${e.message}",
                "deleteFailed",
                e,
            )
        }
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /**
     * The wrapping key, generated on first use.
     *
     * Synchronised because two callers racing here would each generate a key
     * and the second would overwrite the first, rendering anything sealed under
     * the first permanently unreadable.
     */
    @Synchronized
    private fun wrappingKey(): SecretKey {
        val existing = keystore().getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)

        // StrongBox is a separate security chip and is the strongest form of
        // "wrapped by a hardware-protected key where the platform provides one"
        // (REQ-024). Most devices do not have it, and asking for it there
        // throws rather than degrading, so the TEE-backed key is the fallback —
        // still non-exportable, still hardware-held.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generator.init(keySpec(strongBox = true))
                return generator.generateKey()
            } catch (_: ProviderException) {
                // StrongBoxUnavailableException extends ProviderException, and
                // is caught by its supertype so this compiles and runs on API
                // levels that predate the subclass.
            }
        }

        generator.init(keySpec(strongBox = false))
        return generator.generateKey()
    }

    private fun keySpec(strongBox: Boolean): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()

    /**
     * `version ‖ ivLen ‖ iv ‖ ciphertext`, Base64.
     *
     * The IV is the one the provider generated for this operation and is never
     * supplied by us: GCM fails catastrophically on IV reuse, and letting the
     * Keystore pick is the only way to be sure it does not happen.
     */
    private fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        val blob = ByteArray(2 + iv.size + ciphertext.size)
        blob[0] = FORMAT_V1
        blob[1] = iv.size.toByte()
        System.arraycopy(iv, 0, blob, 2, iv.size)
        System.arraycopy(ciphertext, 0, blob, 2 + iv.size, ciphertext.size)

        return Base64.encodeToString(blob, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val blob = Base64.decode(encoded, Base64.NO_WRAP)

        require(blob.isNotEmpty() && blob[0] == FORMAT_V1) {
            "unrecognised record format"
        }
        val ivLength = blob[1].toInt()
        require(ivLength in 1..16 && blob.size > 2 + ivLength) {
            "record header is malformed"
        }

        val iv = blob.copyOfRange(2, 2 + ivLength)
        val ciphertext = blob.copyOfRange(2 + ivLength, blob.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(TAG_BITS, iv))

        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }
}
