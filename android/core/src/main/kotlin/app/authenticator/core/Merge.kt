package app.authenticator.core

import java.security.SecureRandom

/**
 * Joining imported accounts and logins into the existing ones without
 * duplicates. Same rules as the Windows app (windows/src/merge.rs).
 */
object Merge {
    private val random = SecureRandom()

    /** Random id for accounts and logins (32 hex characters). */
    fun newId(): String {
        val bytes = ByteArray(16).also(random::nextBytes)
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    data class Report(
        val accountsAdded: Int = 0,
        val accountsSkipped: Int = 0,
        val loginsAdded: Int = 0,
        val loginsUpdated: Int = 0,
        val loginsSkipped: Int = 0,
    ) {
        /** "2 accounts and 5 passwords added, 1 password updated, 3 already here." */
        fun summary(): String {
            fun plural(n: Int, one: String, many: String) = "$n ${if (n == 1) one else many}"
            val added = buildList {
                if (accountsAdded > 0) add(plural(accountsAdded, "account", "accounts"))
                if (loginsAdded > 0) add(plural(loginsAdded, "password", "passwords"))
            }
            val parts = buildList {
                if (added.isNotEmpty()) add("${added.joinToString(" and ")} added")
                if (loginsUpdated > 0) add("${plural(loginsUpdated, "password", "passwords")} updated")
                val skipped = accountsSkipped + loginsSkipped
                if (skipped > 0) add("$skipped already here")
            }
            if (parts.isEmpty()) return "Nothing to import"
            return parts.joinToString(", ").replaceFirstChar { it.uppercase() } + "."
        }
    }

    class Result(val accounts: List<Account>, val logins: List<Login>, val changed: Boolean)

    /** Gives every account and login a unique id and fills missing dates. */
    fun ensureIds(accounts: List<Account>, logins: List<Login>, now: Long = Otp.nowSeconds()): Result {
        var changed = false
        val seen = HashSet<String>()
        val fixedAccounts = accounts.map { a ->
            if (a.id.isEmpty() || !seen.add(a.id)) {
                changed = true
                a.copy(id = newId()).also { seen.add(it.id) }
            } else a
        }
        val accountIds = seen.toSet()
        val seenLogins = HashSet<String>()
        val fixedLogins = logins.map { l ->
            var x = l
            if (x.id.isEmpty() || !seenLogins.add(x.id)) {
                x = x.copy(id = newId()).also { seenLogins.add(it.id) }
            }
            if (x.otp.isNotEmpty() && x.otp !in accountIds) x = x.copy(otp = "")
            if (x.created == 0L) x = x.copy(created = if (x.modified > 0) x.modified else now)
            if (x.modified == 0L) x = x.copy(modified = x.created)
            if (x != l) changed = true
            x
        }
        return Result(fixedAccounts, fixedLogins, changed)
    }

    class Merged(val accounts: List<Account>, val logins: List<Login>, val report: Report)

    /**
     * Accounts already present (same id, or same secret and labels) are
     * skipped, keeping the higher HOTP counter. A login with the same id
     * replaces the existing one only if it was edited more recently; same
     * website + username + password is a duplicate. Links follow the accounts.
     */
    fun merge(
        accounts: List<Account>,
        logins: List<Login>,
        newAccounts: List<Account>,
        newLogins: List<Login>,
        now: Long = Otp.nowSeconds(),
    ): Merged {
        val outAccounts = accounts.toMutableList()
        val outLogins = logins.toMutableList()
        val idMap = HashMap<String, String>()
        var report = Report()

        for (incoming in newAccounts) {
            val index = outAccounts.indexOfFirst { (incoming.id.isNotEmpty() && it.id == incoming.id) || it.sameAs(incoming) }
            if (index >= 0) {
                val existing = outAccounts[index]
                if (existing.type == OtpType.HOTP && incoming.type == OtpType.HOTP && incoming.counter > existing.counter) {
                    outAccounts[index] = existing.copy(counter = incoming.counter)
                }
                if (incoming.id.isNotEmpty()) idMap[incoming.id] = existing.id
                report = report.copy(accountsSkipped = report.accountsSkipped + 1)
                continue
            }
            val id = if (incoming.id.isEmpty() || outAccounts.any { it.id == incoming.id }) newId() else incoming.id
            if (incoming.id.isNotEmpty()) idMap[incoming.id] = id
            outAccounts.add(incoming.copy(id = id))
            report = report.copy(accountsAdded = report.accountsAdded + 1)
        }

        for (original in newLogins) {
            var incoming = original
            if (incoming.otp.isNotEmpty()) {
                val mapped = idMap[incoming.otp] ?: incoming.otp
                incoming = incoming.copy(otp = if (outAccounts.any { it.id == mapped }) mapped else "")
            }
            if (incoming.created == 0L) incoming = incoming.copy(created = now)
            if (incoming.modified == 0L) incoming = incoming.copy(modified = incoming.created)
            if (incoming.id.isNotEmpty()) {
                val index = outLogins.indexOfFirst { it.id == incoming.id }
                if (index >= 0) {
                    report = if (incoming.modified > outLogins[index].modified) {
                        outLogins[index] = incoming
                        report.copy(loginsUpdated = report.loginsUpdated + 1)
                    } else {
                        report.copy(loginsSkipped = report.loginsSkipped + 1)
                    }
                    continue
                }
            }
            if (outLogins.any { it.sameAs(incoming) }) {
                report = report.copy(loginsSkipped = report.loginsSkipped + 1)
                continue
            }
            if (incoming.id.isEmpty()) incoming = incoming.copy(id = newId())
            outLogins.add(incoming)
            report = report.copy(loginsAdded = report.loginsAdded + 1)
        }
        return Merged(outAccounts, outLogins, report)
    }
}
