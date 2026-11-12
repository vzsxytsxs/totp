package app.authenticator.core

/** RFC 4648 base32, the encoding used for OTP secrets. */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** Upper case, without padding. */
    fun encode(data: ByteArray): String {
        val out = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = ((buffer shl 8) or (b.toInt() and 0xff)) and 0xffff
            bits += 8
            while (bits >= 5) {
                bits -= 5
                out.append(ALPHABET[(buffer shr bits) and 31])
            }
        }
        if (bits > 0) out.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return out.toString()
    }

    /** Tolerates lower case, spaces, dashes and optional `=` padding. */
    fun decode(input: String): ByteArray {
        val out = java.io.ByteArrayOutputStream(input.length * 5 / 8)
        var buffer = 0
        var bits = 0
        var count = 0
        var seenPadding = false
        for (c in input) {
            if (c.isWhitespace() || c == '-') continue
            if (c == '=') {
                seenPadding = true
                continue
            }
            if (seenPadding) throw OtpException("Invalid secret: characters after '=' padding")
            val value = when (val u = c.uppercaseChar()) {
                in 'A'..'Z' -> u - 'A'
                in '2'..'7' -> u - '2' + 26
                else -> throw OtpException("Invalid character '$c' in secret (allowed: A-Z, 2-7)")
            }
            count++
            buffer = ((buffer shl 5) or value) and 0xffff
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write((buffer shr bits) and 0xff)
            }
        }
        if (count == 0) throw OtpException("Secret is empty")
        return out.toByteArray()
    }
}

/** Error with a message suitable for showing to the user. */
class OtpException(message: String) : Exception(message)
