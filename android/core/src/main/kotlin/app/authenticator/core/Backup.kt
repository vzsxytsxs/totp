package app.authenticator.core

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.security.SecureRandom
import java.text.Normalizer
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password-protected backup file shared with the Windows app:
 * Argon2id (password -> 256-bit key) + AES-256-GCM. See docs/backup-format.md.
 */
object Backup {
    const val FORMAT = "authenticator-backup"
    const val MIN_PASSWORD_LENGTH = 8
    private const val VERSION = 1
    private const val SALT_LENGTH = 16
    private const val NONCE_LENGTH = 12

    data class KdfParams(val memoryKib: Int, val iterations: Int, val parallelism: Int) {
        fun isAcceptable() = memoryKib in 8 * 1024..1024 * 1024 && iterations in 1..16 && parallelism in 1..16

        companion object {
            val DEFAULT = KdfParams(memoryKib = 64 * 1024, iterations = 3, parallelism = 1)
        }
    }

    enum class Failure { WRONG_FORMAT, UNSUPPORTED, WRONG_PASSWORD, CORRUPT }

    class BackupException(val failure: Failure, message: String) : Exception(message)

    class Restored(val accounts: List<Account>, val invalidEntries: Int)

    private val random = SecureRandom()

    /** NFC so the same password typed on different keyboards gives the same key. */
    fun deriveKey(password: String, salt: ByteArray, params: KdfParams): ByteArray {
        val pwd = Normalizer.normalize(password, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
        val generator = Argon2BytesGenerator()
        generator.init(
            Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(params.memoryKib)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .withSalt(salt)
                .build(),
        )
        val key = ByteArray(32)
        generator.generateBytes(pwd, key)
        pwd.fill(0)
        return key
    }

    private fun aad() = "$FORMAT:v$VERSION".toByteArray(Charsets.UTF_8)

    /** Returns the backup file contents (JSON text). */
    fun create(accounts: List<Account>, password: String, params: KdfParams = KdfParams.DEFAULT): String {
        val salt = ByteArray(SALT_LENGTH).also(random::nextBytes)
        val nonce = ByteArray(NONCE_LENGTH).also(random::nextBytes)
        val key = deriveKey(password, salt, params)
        val entries = JSONArray()
        accounts.forEach { entries.put(it.toJson()) }
        val plaintext = JSONObject().put("version", 1).put("entries", entries).toString().toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad())
        val ciphertext = cipher.doFinal(plaintext)
        key.fill(0)
        plaintext.fill(0)
        val b64 = Base64.getEncoder()
        return JSONObject()
            .put("format", FORMAT)
            .put("version", VERSION)
            .put(
                "kdf",
                JSONObject()
                    .put("algorithm", "argon2id")
                    .put("memory_kib", params.memoryKib)
                    .put("iterations", params.iterations)
                    .put("parallelism", params.parallelism)
                    .put("salt", b64.encodeToString(salt)),
            )
            .put("cipher", JSONObject().put("algorithm", "aes-256-gcm").put("nonce", b64.encodeToString(nonce)))
            .put("data", b64.encodeToString(ciphertext))
            .toString(2)
    }

    fun open(contents: ByteArray, password: String): Restored {
        val envelope = try {
            JSONObject(String(contents, Charsets.UTF_8))
        } catch (e: JSONException) {
            throw BackupException(Failure.WRONG_FORMAT, "This is not an Authenticator backup file")
        }
        if (envelope.optString("format") != FORMAT) {
            throw BackupException(Failure.WRONG_FORMAT, "This is not an Authenticator backup file")
        }
        val version = envelope.optInt("version", -1)
        if (version != VERSION) throw BackupException(Failure.UNSUPPORTED, "Unsupported backup version $version. Update the app.")
        val kdf = envelope.optJSONObject("kdf") ?: throw corrupt("missing kdf")
        val cipherInfo = envelope.optJSONObject("cipher") ?: throw corrupt("missing cipher")
        if (kdf.optString("algorithm") != "argon2id" || cipherInfo.optString("algorithm") != "aes-256-gcm") {
            throw BackupException(Failure.UNSUPPORTED, "Unsupported encryption. Update the app.")
        }
        val params = KdfParams(kdf.optInt("memory_kib"), kdf.optInt("iterations"), kdf.optInt("parallelism"))
        if (!params.isAcceptable()) throw BackupException(Failure.UNSUPPORTED, "Unsupported key derivation parameters")
        val b64 = Base64.getDecoder()
        val salt = decode(b64, kdf.optString("salt"), "salt")
        val nonce = decode(b64, cipherInfo.optString("nonce"), "nonce")
        val data = decode(b64, envelope.optString("data"), "data")
        if (salt.size !in SALT_LENGTH..64) throw corrupt("invalid salt")
        if (nonce.size != NONCE_LENGTH) throw corrupt("invalid nonce")

        val key = deriveKey(password, salt, params)
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad())
            cipher.doFinal(data)
        } catch (e: AEADBadTagException) {
            throw BackupException(Failure.WRONG_PASSWORD, "Wrong password")
        } finally {
            key.fill(0)
        }
        try {
            val payload = JSONObject(String(plaintext, Charsets.UTF_8))
            if (payload.optInt("version", -1) != 1) throw BackupException(Failure.UNSUPPORTED, "Unsupported backup contents")
            val entries = payload.getJSONArray("entries")
            val accounts = mutableListOf<Account>()
            var invalid = 0
            for (i in 0 until entries.length()) {
                val account = runCatching { Account.fromJson(entries.getJSONObject(i)) }.getOrNull()
                if (account != null && account.validationError() == null) accounts.add(account) else invalid++
            }
            return Restored(accounts, invalid)
        } catch (e: JSONException) {
            throw corrupt(e.message ?: "invalid contents")
        } finally {
            plaintext.fill(0)
        }
    }

    private fun decode(b64: Base64.Decoder, text: String, what: String): ByteArray = try {
        b64.decode(text)
    } catch (e: IllegalArgumentException) {
        throw corrupt("invalid $what")
    }

    private fun corrupt(why: String) = BackupException(Failure.CORRUPT, "The file is damaged: $why")
}
