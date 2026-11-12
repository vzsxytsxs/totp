package app.authenticator.core

import java.util.Base64

/**
 * Google Authenticator "Transfer accounts" format:
 * `otpauth-migration://offline?data=<base64 protobuf MigrationPayload>`.
 *
 * ```
 * MigrationPayload { repeated OtpParameters otp_parameters = 1; int32 version = 2;
 *                    int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5; }
 * OtpParameters { bytes secret = 1; string name = 2; string issuer = 3;
 *                 Algorithm algorithm = 4;  // 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
 *                 DigitCount digits = 5;    // 1 six, 2 eight
 *                 OtpType type = 6;         // 1 HOTP, 2 TOTP
 *                 int64 counter = 7; }
 * ```
 */
object Migration {
    data class BatchInfo(val index: Int, val size: Int, val id: Int)

    class Batch(val accounts: List<Account>, val skipped: List<String>, val info: BatchInfo)

    private const val PREFIX = "otpauth-migration://"

    /** Payload bytes per QR code; keeps codes dense enough to scan from a screen. */
    private const val MAX_BATCH_BYTES = 600

    fun isMigrationUri(text: String) = text.trim().startsWith(PREFIX, ignoreCase = true)

    fun decodeUri(uri: String): Batch {
        val trimmed = uri.trim()
        if (!isMigrationUri(trimmed)) throw OtpException("Not a Google Authenticator export code")
        val query = trimmed.substringAfter('?', "")
        val raw = query.split('&')
            .firstOrNull { it.substringBefore('=').equals("data", ignoreCase = true) }
            ?.substringAfter('=')
            ?: throw OtpException("The export code has no data")
        // Only `+` must survive: it is part of the base64 alphabet.
        val data = OtpAuth.percentDecode(raw, false).trim().replace(' ', '+')
            .replace('-', '+').replace('_', '/')
        val bytes = try {
            Base64.getDecoder().decode(data)
        } catch (e: IllegalArgumentException) {
            throw OtpException("The export code data is not valid base64")
        }
        return decodePayload(bytes)
    }

    private class Reader(private val buf: ByteArray, private var pos: Int = 0, private val end: Int = buf.size) {
        fun done() = pos >= end

        fun varint(): Long {
            var result = 0L
            var shift = 0
            while (shift < 64) {
                if (pos >= end) throw OtpException("Export code is truncated")
                val b = buf[pos++].toInt()
                result = result or ((b and 0x7f).toLong() shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
            }
            throw OtpException("Export code is corrupt")
        }

        fun bytes(): ByteArray {
            val len = varint()
            if (len < 0 || len > end - pos) throw OtpException("Export code is truncated")
            val out = buf.copyOfRange(pos, pos + len.toInt())
            pos += len.toInt()
            return out
        }

        fun skip(wireType: Int) {
            when (wireType) {
                0 -> varint()
                1 -> pos += 8
                2 -> bytes()
                5 -> pos += 4
                else -> throw OtpException("Export code is corrupt")
            }
            if (pos > end) throw OtpException("Export code is truncated")
        }
    }

    private fun decodePayload(buf: ByteArray): Batch {
        val accounts = mutableListOf<Account>()
        val skipped = mutableListOf<String>()
        var size = 1
        var index = 0
        var id = 0
        val r = Reader(buf)
        while (!r.done()) {
            val key = r.varint()
            val field = (key ushr 3).toInt()
            val wire = (key and 7).toInt()
            when {
                field == 1 && wire == 2 -> {
                    val result = decodeOtpParameters(r.bytes())
                    result.first?.let(accounts::add)
                    result.second?.let(skipped::add)
                }
                field == 3 && wire == 0 -> size = r.varint().toInt()
                field == 4 && wire == 0 -> index = r.varint().toInt()
                field == 5 && wire == 0 -> id = r.varint().toInt()
                else -> r.skip(wire)
            }
        }
        return Batch(accounts, skipped, BatchInfo(index, size.coerceAtLeast(1), id))
    }

    /** Returns (account, null) or (null, reason it cannot be used). */
    private fun decodeOtpParameters(buf: ByteArray): Pair<Account?, String?> {
        var secret = ByteArray(0)
        var name = ""
        var issuer = ""
        var algorithm = 0L
        var digits = 0L
        var type = 0L
        var counter = 0L
        val r = Reader(buf)
        while (!r.done()) {
            val key = r.varint()
            val field = (key ushr 3).toInt()
            val wire = (key and 7).toInt()
            when {
                field == 1 && wire == 2 -> secret = r.bytes()
                field == 2 && wire == 2 -> name = String(r.bytes(), Charsets.UTF_8)
                field == 3 && wire == 2 -> issuer = String(r.bytes(), Charsets.UTF_8)
                field == 4 && wire == 0 -> algorithm = r.varint()
                field == 5 && wire == 0 -> digits = r.varint()
                field == 6 && wire == 0 -> type = r.varint()
                field == 7 && wire == 0 -> counter = r.varint()
                else -> r.skip(wire)
            }
        }
        // Google puts "Issuer:name" in the name field when an issuer exists.
        issuer = issuer.trim()
        name = name.trim()
        if (issuer.isNotEmpty() && name.startsWith("$issuer:")) name = name.substring(issuer.length + 1).trim()
        val label = if (issuer.isEmpty()) name else "$issuer ($name)"
        val alg = when (algorithm) {
            0L, 1L -> HashAlgorithm.SHA1
            2L -> HashAlgorithm.SHA256
            3L -> HashAlgorithm.SHA512
            else -> return null to "$label: unsupported algorithm (MD5)"
        }
        val digitCount = when (digits) {
            0L, 1L -> 6
            2L -> 8
            else -> return null to "$label: unsupported digit count"
        }
        val account = Account(
            type = if (type == 1L) OtpType.HOTP else OtpType.TOTP,
            issuer = issuer,
            name = name,
            secret = secret,
            algorithm = alg,
            digits = digitCount,
            period = 30,
            counter = counter,
        )
        val error = account.validationError()
        return if (error == null) account to null else null to "$label: $error"
    }

    /** Google Authenticator's format has no period field and only 6 or 8 digits. */
    fun exportable(a: Account): Boolean =
        (a.type == OtpType.HOTP || a.period == 30) && (a.digits == 6 || a.digits == 8)

    private class Writer {
        val out = java.io.ByteArrayOutputStream()
        fun varint(value: Long) {
            var v = value
            while (v and 0x7fL.inv() != 0L) {
                out.write(((v and 0x7f) or 0x80).toInt())
                v = v ushr 7
            }
            out.write(v.toInt())
        }
        fun bytes(field: Int, data: ByteArray) {
            varint(((field shl 3) or 2).toLong())
            varint(data.size.toLong())
            out.write(data)
        }
        fun uint(field: Int, value: Long) {
            varint((field shl 3).toLong())
            varint(value)
        }
    }

    private fun encodeOtpParameters(a: Account): ByteArray {
        val w = Writer()
        w.bytes(1, a.secret)
        w.bytes(2, a.name.toByteArray(Charsets.UTF_8))
        if (a.issuer.isNotEmpty()) w.bytes(3, a.issuer.toByteArray(Charsets.UTF_8))
        w.uint(4, when (a.algorithm) { HashAlgorithm.SHA1 -> 1; HashAlgorithm.SHA256 -> 2; HashAlgorithm.SHA512 -> 3 })
        w.uint(5, if (a.digits == 8) 2 else 1)
        w.uint(6, if (a.type == OtpType.HOTP) 1 else 2)
        if (a.type == OtpType.HOTP) w.uint(7, a.counter)
        return w.out.toByteArray()
    }

    /** Builds one `otpauth-migration://` URI per QR code. Callers filter with [exportable]. */
    fun encodeUris(accounts: List<Account>, batchId: Int): List<String> {
        val groups = mutableListOf<MutableList<ByteArray>>()
        var size = 0
        for (entry in accounts.map(::encodeOtpParameters)) {
            val cost = entry.size + 3
            if (groups.isEmpty() || (size + cost > MAX_BATCH_BYTES && groups.last().isNotEmpty())) {
                groups.add(mutableListOf())
                size = 0
            }
            groups.last().add(entry)
            size += cost
        }
        return groups.mapIndexed { index, group ->
            val w = Writer()
            group.forEach { w.bytes(1, it) }
            w.uint(2, 1)
            w.uint(3, groups.size.toLong())
            w.uint(4, index.toLong())
            w.uint(5, batchId.toLong() and 0xffffffffL)
            val b64 = Base64.getEncoder().encodeToString(w.out.toByteArray())
            "otpauth-migration://offline?data=" + b64.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        }
    }
}
