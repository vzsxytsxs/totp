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

    /** Percent-encodes everything except RFC 3986 unreserved characters. */
    fun percentEncode(input: String): String {
        val sb = StringBuilder()
        for (b in input.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xff
            if ((c in 'a'.code..'z'.code) || (c in 'A'.code..'Z'.code) || (c in '0'.code..'9'.code) || c.toChar() in "-._~") {
                sb.append(c.toChar())
            } else {
                sb.append('%').append("%02X".format(c))
            }
        }
        return sb.toString()
    }

    /** Builds the `otpauth://` link for one account (same output as the Windows app). */
    fun format(account: Account): String {
        val label = when {
            account.issuer.isNotEmpty() && account.name.isNotEmpty() ->
                percentEncode(account.issuer) + ":" + percentEncode(account.name)
            account.issuer.isNotEmpty() -> percentEncode(account.issuer) + ":"
            else -> percentEncode(account.name)
        }
        val sb = StringBuilder("otpauth://").append(account.type.jsonName).append('/').append(label)
            .append("?secret=").append(Base32.encode(account.secret))
        if (account.issuer.isNotEmpty()) sb.append("&issuer=").append(percentEncode(account.issuer))
        if (account.algorithm != HashAlgorithm.SHA1) sb.append("&algorithm=").append(account.algorithm.jsonName)
        if (account.digits != 6) sb.append("&digits=").append(account.digits)
        when (account.type) {
            OtpType.TOTP -> if (account.period != 30) sb.append("&period=").append(account.period)
            OtpType.HOTP -> sb.append("&counter=").append(account.counter)
        }
        return sb.toString()
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
