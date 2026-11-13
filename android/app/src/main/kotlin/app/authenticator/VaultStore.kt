package app.authenticator

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import app.authenticator.core.Account
import app.authenticator.core.Login
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class VaultException(message: String) : Exception(message)

/** Everything kept in the vault: 2FA accounts and saved website logins. */
class VaultData(val accounts: List<Account>, val logins: List<Login>)

/**
 * Accounts and logins stored in the app's private files, encrypted with AES-256-GCM using
 * a key that lives in the Android Keystore (hardware-backed on most phones), so
 * the file is useless if copied off the device.
 */
class VaultStore(context: Context) {
    private val path = File(context.filesDir, "vault.bin")
    private val file = AtomicFile(path)

    fun exists(): Boolean = path.exists()

    @Synchronized
    fun load(): VaultData {
        if (!exists()) return VaultData(emptyList(), emptyList())
        val bytes = file.readFully()
        val headerSize = MAGIC.size + IV_SIZE
        if (bytes.size < headerSize + 16 || !bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            throw VaultException("The stored data has an unknown format.")
        }
        val key = key(create = false)
            ?: throw VaultException("The encryption key for the stored data is missing (were the app's files restored from another phone?).")
        val plaintext = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes, MAGIC.size, IV_SIZE))
            cipher.updateAAD(AAD)
            cipher.doFinal(bytes, headerSize, bytes.size - headerSize)
        } catch (e: Exception) {
            throw VaultException("The stored data could not be decrypted (${e.javaClass.simpleName}).")
        }
        try {
            val json = JSONObject(String(plaintext, Charsets.UTF_8))
            val entries = json.getJSONArray("entries")
            val logins = json.optJSONArray("logins") ?: JSONArray()
            return VaultData(
                accounts = (0 until entries.length()).map { Account.fromJson(entries.getJSONObject(it)) },
                logins = (0 until logins.length()).map { Login.fromJson(logins.getJSONObject(it)) },
            )
        } finally {
            plaintext.fill(0)
        }
    }

    @Synchronized
    fun save(accounts: List<Account>, logins: List<Login>) {
        val entries = JSONArray()
        accounts.forEach { entries.put(it.toJson()) }
        val loginArray = JSONArray()
        logins.forEach { loginArray.put(it.toJson()) }
        // Older versions read only "entries" and ignore the rest.
        val plaintext = JSONObject().put("version", 1).put("entries", entries).put("logins", loginArray)
            .toString().toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(create = true))
        cipher.updateAAD(AAD)
        val ciphertext = cipher.doFinal(plaintext)
        plaintext.fill(0)
        val iv = cipher.iv
        check(iv.size == IV_SIZE) { "Unexpected IV size" }
        val out = file.startWrite()
        try {
            out.write(MAGIC)
            out.write(iv)
            out.write(ciphertext)
            file.finishWrite(out)
        } catch (e: IOException) {
            file.failWrite(out)
            throw e
        }
    }

    /** Deletes the data and the key (used by "reset" when data cannot be read). */
    @Synchronized
    fun destroy() {
        file.delete()
        runCatching { keyStore().deleteEntry(KEY_ALIAS) }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(create: Boolean): SecretKey? {
        (keyStore().getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY_ALIAS = "authenticator.vault.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_SIZE = 12
        val MAGIC = "AUTHV1".toByteArray(Charsets.US_ASCII)
        val AAD = "authenticator-android-vault:v1".toByteArray(Charsets.US_ASCII)
    }
}

/** Non-secret preferences. */
data class AppSettings(
    val appLock: Boolean = true,
    val lockDelaySeconds: Int = 30,
    val blockScreenshots: Boolean = true,
    val clearClipboard: Boolean = true,
)

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun load() = AppSettings(
        appLock = prefs.getBoolean("app_lock", true),
        lockDelaySeconds = prefs.getInt("lock_delay", 30),
        blockScreenshots = prefs.getBoolean("block_screenshots", true),
        clearClipboard = prefs.getBoolean("clear_clipboard", true),
    )

    fun save(s: AppSettings) {
        prefs.edit()
            .putBoolean("app_lock", s.appLock)
            .putInt("lock_delay", s.lockDelaySeconds)
            .putBoolean("block_screenshots", s.blockScreenshots)
            .putBoolean("clear_clipboard", s.clearClipboard)
            .apply()
    }
}
