package app.authenticator.core

import org.json.JSONObject
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class OtpType(val jsonName: String) {
    TOTP("totp"),
    HOTP("hotp");

    companion object {
        fun fromJson(name: String): OtpType =
            entries.firstOrNull { it.jsonName.equals(name, ignoreCase = true) }
                ?: throw OtpException("Unsupported OTP type '$name'")
    }
}

enum class HashAlgorithm(val jsonName: String, val macName: String) {
    SHA1("SHA1", "HmacSHA1"),
    SHA256("SHA256", "HmacSHA256"),
    SHA512("SHA512", "HmacSHA512");

    companion object {
        fun parse(name: String): HashAlgorithm? {
            val normalized = name.trim().uppercase().replace("-", "")
            return entries.firstOrNull { it.jsonName == normalized }
        }
    }
}

/**
 * One OTP account. [toJson]/[fromJson] produce exactly the JSON shape used in
 * backups, shared with the Windows app (see docs/backup-format.md).
 */
data class Account(
    val type: OtpType = OtpType.TOTP,
    val issuer: String = "",
    val name: String = "",
    val secret: ByteArray,
    val algorithm: HashAlgorithm = HashAlgorithm.SHA1,
    val digits: Int = 6,
    val period: Int = 30,
    val counter: Long = 0,
    /** Stable random id; empty in backups written before version 2.0. */
    val id: String = "",
) {
    /** Returns an error message, or null when the parameters are usable. */
    fun validationError(): String? = when {
        secret.isEmpty() -> "Secret is empty"
        digits !in 6..8 -> "Unsupported number of digits: $digits"
        type == OtpType.TOTP && period !in 1..600 -> "Unsupported period: $period"
        counter < 0 -> "Invalid counter"
        issuer.length > 256 || name.length > 256 -> "Name or issuer is too long"
        else -> null
    }

    fun validate(): Account {
        validationError()?.let { throw OtpException(it) }
        return this
    }

    val displayTitle: String
        get() = when {
            issuer.isNotEmpty() -> issuer
            name.isNotEmpty() -> name
            else -> "(no name)"
        }

    /** Code for [unixSeconds] (TOTP) or for the stored counter (HOTP). */
    fun codeAt(unixSeconds: Long): String {
        val movingFactor = when (type) {
            OtpType.TOTP -> unixSeconds / period.coerceAtLeast(1)
            OtpType.HOTP -> counter
        }
        return Otp.hotp(secret, movingFactor, digits, algorithm)
    }

    fun secondsRemaining(unixSeconds: Long): Int {
        val p = period.coerceAtLeast(1)
        return (p - (unixSeconds % p)).toInt()
    }

    /** Same secret and labels: used to skip duplicates when importing. */
    fun sameAs(other: Account): Boolean =
        secret.contentEquals(other.secret) && type == other.type && issuer == other.issuer && name == other.name

    /** Standard `otpauth://` link (QR code for a single account). */
    fun toOtpAuth(): String = OtpAuth.format(this)

    fun toJson(): JSONObject = JSONObject()
        .also { if (id.isNotEmpty()) it.put("id", id) }
        .put("type", type.jsonName)
        .put("issuer", issuer)
        .put("name", name)
        .put("secret", Base32.encode(secret))
        .put("algorithm", algorithm.jsonName)
        .put("digits", digits)
        .put("period", period)
        .put("counter", counter)

    override fun equals(other: Any?): Boolean =
        other is Account && type == other.type && issuer == other.issuer && name == other.name &&
            secret.contentEquals(other.secret) && algorithm == other.algorithm && digits == other.digits &&
            period == other.period && counter == other.counter && id == other.id

    override fun hashCode(): Int =
        listOf(id, type, issuer, name, secret.contentHashCode(), algorithm, digits, period, counter).hashCode()

    override fun toString(): String =
        "Account(id=$id, type=$type, issuer=$issuer, name=$name, secret=<redacted>, algorithm=$algorithm, " +
            "digits=$digits, period=$period, counter=$counter)"

    companion object {
        fun fromJson(json: JSONObject): Account = Account(
            type = OtpType.fromJson(json.optString("type", "totp")),
            issuer = json.optString("issuer", ""),
            name = json.optString("name", ""),
            secret = Base32.decode(json.getString("secret")),
            algorithm = HashAlgorithm.parse(json.optString("algorithm", "SHA1"))
                ?: throw OtpException("Unsupported algorithm"),
            digits = json.optInt("digits", 6),
            period = json.optInt("period", 30),
            counter = json.optLong("counter", 0),
            id = json.optString("id", ""),
        )
    }
}

object Otp {
    /** RFC 4226 HOTP value. */
    fun hotp(secret: ByteArray, counter: Long, digits: Int, algorithm: HashAlgorithm): String {
        val mac = Mac.getInstance(algorithm.macName)
        mac.init(SecretKeySpec(secret, algorithm.macName))
        val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        val offset = hash[hash.size - 1].toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)
        hash.fill(0)
        var modulus = 1
        repeat(digits) { modulus *= 10 }
        return (binary % modulus).toString().padStart(digits, '0')
    }

    fun nowSeconds(): Long = System.currentTimeMillis() / 1000
}
