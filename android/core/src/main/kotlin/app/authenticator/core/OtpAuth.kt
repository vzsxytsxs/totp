package app.authenticator.core

/** Parsing of `otpauth://` links and of anything a QR code may contain. */
object OtpAuth {
    fun percentDecode(input: String, plusIsSpace: Boolean): String {
        val bytes = input.toByteArray(Charsets.UTF_8)
        val out = java.io.ByteArrayOutputStream(bytes.size)
        var i = 0
        while (i < bytes.size) {
            val b = bytes[i]
            when {
                b == '%'.code.toByte() && i + 2 < bytes.size -> {
                    val hex = String(bytes, i + 1, 2, Charsets.US_ASCII).toIntOrNull(16)
                    if (hex != null) {
                        out.write(hex)
                        i += 3
                        continue
                    }
                    out.write(b.toInt())
                }
                b == '+'.code.toByte() && plusIsSpace -> out.write(' '.code)
                else -> out.write(b.toInt())
            }
            i++
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    fun queryPairs(query: String): List<Pair<String, String>> =
        query.split('&').filter { it.isNotEmpty() }.map { pair ->
            val idx = pair.indexOf('=')
            val key = if (idx >= 0) pair.substring(0, idx) else pair
            val value = if (idx >= 0) pair.substring(idx + 1) else ""
            percentDecode(key, true).lowercase() to percentDecode(value, true)
        }

    /** Parses `otpauth://totp/Issuer:name?secret=...&issuer=...`. */
    fun parse(uri: String): Account {
        val trimmed = uri.trim()
        if (!trimmed.startsWith("otpauth://", ignoreCase = true)) throw OtpException("Not an otpauth:// link")
        val rest = trimmed.substring("otpauth://".length)
        val slash = rest.indexOf('/')
        if (slash < 0) throw OtpException("Malformed otpauth link")
        val type = when (val t = rest.substring(0, slash).lowercase()) {
            "totp" -> OtpType.TOTP
            "hotp" -> OtpType.HOTP
            else -> throw OtpException("Unsupported OTP type '$t'")
        }
        val afterType = rest.substring(slash + 1)
        val q = afterType.indexOf('?')
        val label = percentDecode(if (q >= 0) afterType.substring(0, q) else afterType, false)
        val query = if (q >= 0) afterType.substring(q + 1) else ""
        val colon = label.indexOf(':')
        var issuer = if (colon >= 0) label.substring(0, colon).trim() else ""
        val name = if (colon >= 0) label.substring(colon + 1).trim() else label.trim()

        var secret: ByteArray? = null
        var algorithm = HashAlgorithm.SHA1
        var digits = 6
        var period = 30
        var counter: Long? = null
        for ((key, value) in queryPairs(query)) {
            when (key) {
                "secret" -> secret = Base32.decode(value)
                "issuer" -> if (value.isNotBlank()) issuer = value.trim()
                "algorithm" -> algorithm = HashAlgorithm.parse(value)
                    ?: throw OtpException("Unsupported algorithm '$value'")
                "digits" -> digits = value.trim().toIntOrNull() ?: throw OtpException("Invalid digits value")
                "period" -> period = value.trim().toIntOrNull() ?: throw OtpException("Invalid period value")
                "counter" -> counter = value.trim().toLongOrNull() ?: throw OtpException("Invalid counter value")
            }
        }
        if (secret == null) throw OtpException("The link has no secret")
        if (type == OtpType.HOTP && counter == null) throw OtpException("HOTP link has no counter")
        return Account(type, issuer, name, secret, algorithm, digits, period, counter ?: 0).validate()
    }
}

/** Accounts found in a scanned/pasted QR code or text. */
data class ImportResult(
    val accounts: List<Account>,
    /** Entries that could not be imported, with the reason. */
    val skipped: List<String> = emptyList(),
    /** For Google Authenticator exports split over several QR codes. */
    val batch: Migration.BatchInfo? = null,
)

object ImportParser {
    fun isOtpText(text: String): Boolean = text.trim().startsWith("otpauth", ignoreCase = true)

    /** Interprets an `otpauth://` or `otpauth-migration://` text. */
    fun parse(text: String): ImportResult {
        val trimmed = text.trim()
        return when {
            Migration.isMigrationUri(trimmed) -> {
                val batch = Migration.decodeUri(trimmed)
                ImportResult(batch.accounts, batch.skipped, batch.info)
            }
            trimmed.startsWith("otpauth://", ignoreCase = true) -> ImportResult(listOf(OtpAuth.parse(trimmed)))
            else -> throw OtpException("This QR code is not an authenticator code")
        }
    }
}
