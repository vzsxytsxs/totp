package app.authenticator.core

import org.json.JSONObject
import java.security.SecureRandom

/**
 * One saved website login. [toJson]/[fromJson] produce the JSON shape used in
 * backups (`logins`), shared with the Windows app (see docs/backup-format.md).
 */
data class Login(
    val id: String = "",
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    /** Id of the linked 2FA account, or empty. */
    val otp: String = "",
    /** Unix seconds. */
    val created: Long = 0,
    val modified: Long = 0,
) {
    fun validationError(): String? = when {
        title.isBlank() && url.isBlank() -> "A login needs a title or a website"
        title.length > 256 || username.length > 512 || password.length > 4096 ||
            url.length > 2048 || notes.length > 65536 || otp.length > 64 -> "A field is too long"
        else -> null
    }

    /** Title, or the website's host name when there is no title. */
    val displayTitle: String
        get() = when {
            title.isNotBlank() -> title.trim()
            else -> Site.parse(url)?.host?.removePrefix("www.") ?: url.trim()
        }

    /** Host shown in lists ("github.com"), or empty. */
    val host: String get() = Site.parse(url)?.host ?: ""

    /** Same website, username and password: a duplicate when importing. */
    fun sameAs(other: Login): Boolean = host == other.host && username == other.username && password == other.password

    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("title", title)
        .put("username", username)
        .put("password", password)
        .put("url", url)
        .put("notes", notes)
        .also { if (otp.isNotEmpty()) it.put("otp", otp) }
        .put("created", created)
        .put("modified", modified)

    override fun toString(): String = "Login(id=$id, title=$title, username=$username, password=<redacted>, url=$url)"

    companion object {
        fun fromJson(json: JSONObject) = Login(
            id = json.optString("id", ""),
            title = json.optString("title", ""),
            username = json.optString("username", ""),
            password = json.optString("password", ""),
            url = json.optString("url", ""),
            notes = json.optString("notes", ""),
            otp = json.optString("otp", ""),
            created = json.optLong("created", 0),
            modified = json.optLong("modified", 0),
        )
    }
}

/** Scheme, host and port of a URL, parsed leniently ("github.com" works too). */
data class Site(val scheme: String, val host: String, val port: Int?) {
    companion object {
        fun parse(text: String): Site? {
            val t = text.trim()
            val sep = t.indexOf("://")
            val hasScheme = sep > 0 && t.substring(0, sep).all { it.isLetterOrDigit() || it in "+-." }
            val scheme = if (hasScheme) t.substring(0, sep).lowercase() else ""
            val rest = if (hasScheme) t.substring(sep + 3) else t
            var authority = rest.split('/', '?', '#').first()
            authority = authority.substringAfterLast('@')
            val host: String
            val portText: String?
            if (authority.startsWith("[")) {
                val end = authority.indexOf(']')
                if (end < 0) return null
                host = authority.substring(0, end + 1)
                portText = authority.substring(end + 1).removePrefix(":").takeIf { authority.length > end + 1 }
            } else {
                val colon = authority.lastIndexOf(':')
                host = if (colon >= 0) authority.substring(0, colon) else authority
                portText = if (colon >= 0) authority.substring(colon + 1) else null
            }
            val port = when {
                portText.isNullOrEmpty() -> null
                else -> portText.toIntOrNull()?.takeIf { it in 0..65535 } ?: return null
            }
            val h = host.trimEnd('.').lowercase()
            if (h.isEmpty() || h.any { it.isWhitespace() || it in "\\<>\"'`{}|^%" }) return null
            return Site(scheme, h, port)
        }
    }
}

data class GeneratorOptions(
    val length: Int = 20,
    val lowercase: Boolean = true,
    val uppercase: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    /** Leave out characters that are easy to confuse (Il1O0o). */
    val avoidSimilar: Boolean = false,
)

object PasswordGenerator {
    const val MIN_LENGTH = 4
    const val MAX_LENGTH = 128
    private const val SIMILAR = "Il1O0o"
    private val random = SecureRandom()

    /** Random password with at least one character of each selected kind. */
    fun generate(options: GeneratorOptions = GeneratorOptions()): String {
        val sets = buildList {
            fun add(enabled: Boolean, chars: String) {
                if (!enabled) return
                val set = chars.filter { !options.avoidSimilar || it !in SIMILAR }
                if (set.isNotEmpty()) add(set)
            }
            add(options.lowercase, "abcdefghijklmnopqrstuvwxyz")
            add(options.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            add(options.digits, "0123456789")
            add(options.symbols, "!@#$%^&*()-_=+[]{};:,.?/~")
        }.ifEmpty { listOf("abcdefghijklmnopqrstuvwxyz") }
        val length = options.length.coerceIn(MIN_LENGTH, MAX_LENGTH)
        val all = sets.joinToString("")
        val chars = CharArray(length)
        sets.forEachIndexed { i, set -> chars[i] = set[random.nextInt(set.length)] }
        for (i in sets.size until length) chars[i] = all[random.nextInt(all.length)]
        for (i in chars.size - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp
        }
        return String(chars).also { chars.fill(' ') }
    }
}
