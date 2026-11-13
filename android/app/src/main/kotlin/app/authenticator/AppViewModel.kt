package app.authenticator

import android.app.Application
import android.net.Uri
import android.os.SystemClock
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.authenticator.core.Account
import app.authenticator.core.Backup
import app.authenticator.core.ImportParser
import app.authenticator.core.Login
import app.authenticator.core.Merge
import app.authenticator.core.Migration
import app.authenticator.core.Otp
import app.authenticator.core.OtpException
import app.authenticator.core.OtpType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom

data class Entry(val id: Long, val account: Account)

enum class HomeTab { Codes, Passwords }

sealed interface Screen {
    data object Home : Screen
    data object Scanner : Screen
    data object Manual : Screen
    data object Export : Screen

    /** QR codes to scan; [single] is one account's otpauth:// code (shown from the list). */
    data class ExportQr(val uris: List<String>, val note: String, val single: Boolean = false) : Screen

    /** What goes into an export (ids of accounts and logins). */
    data object ExportChoose : Screen
    data object Settings : Screen

    /** Add ([id] null) or view and edit a saved login. */
    data class LoginEdit(val id: String?) : Screen
}

/** Ids of the accounts and logins chosen for an export. */
data class ExportSelection(val accounts: Set<String>, val logins: Set<String>)

sealed interface ScanOutcome {
    val message: String

    /** Import finished: go back to the list. */
    data class Done(override val message: String) : ScanOutcome

    /** Part of a multi-code Google Authenticator export: keep scanning. */
    data class Continue(override val message: String) : ScanOutcome
    data class Error(override val message: String) : ScanOutcome
}

const val MAX_BACKUP_BYTES = 20 * 1024 * 1024

@OptIn(ExperimentalCoroutinesApi::class)
class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val store = VaultStore(app)
    private val settingsStore = SettingsStore(app)
    private val ioSerial = Dispatchers.IO.limitedParallelism(1)

    var settings by mutableStateOf(settingsStore.load())
        private set
    var locked by mutableStateOf(false)
        private set
    var loaded by mutableStateOf(false)
        private set
    var vaultError by mutableStateOf<String?>(null)
        private set
    var entries by mutableStateOf<List<Entry>>(emptyList())
        private set
    var logins by mutableStateOf<List<Login>>(emptyList())
        private set
    var screen by mutableStateOf<Screen>(Screen.Home)
    var homeTab by mutableStateOf(HomeTab.Codes)
    var exportSelection by mutableStateOf(ExportSelection(emptySet(), emptySet()))
    var busy by mutableStateOf<String?>(null)
        private set
    var scanStatus by mutableStateOf<String?>(null)

    /** Backup file chosen for restore, waiting for its password. */
    var pendingBackup by mutableStateOf<ByteArray?>(null)

    /** Password typed for a backup being saved, waiting for the file location. */
    var pendingExportPassword: String? = null

    /** True while a system screen we opened (picker, prompt) covers the app. */
    var suppressLock = false

    val messages = Channel<String>(Channel.BUFFERED)

    private var nextId = 0L
    private val seenBatches = mutableMapOf<Int, MutableSet<Int>>()
    private var backgroundedAt: Long? = null
    private var pendingLink: String? = null

    init {
        if (settings.appLock && canAuthenticate()) locked = true else load()
    }

    fun canAuthenticate(): Boolean =
        BiometricManager.from(getApplication()).canAuthenticate(BIOMETRIC_WEAK or DEVICE_CREDENTIAL) ==
            BiometricManager.BIOMETRIC_SUCCESS

    val lockActive: Boolean get() = settings.appLock && canAuthenticate()

    fun message(text: String) {
        messages.trySend(text)
    }

    // ---------------------------------------------------------------- lock

    fun unlocked() {
        locked = false
        if (!loaded) load()
    }

    fun lock() {
        if (!lockActive) return
        locked = true
        loaded = false
        entries = emptyList()
        logins = emptyList()
        exportSelection = ExportSelection(emptySet(), emptySet())
        screen = Screen.Home
        pendingBackup = null
        pendingExportPassword = null
        scanStatus = null
        seenBatches.clear()
    }

    fun onStop() {
        if (!suppressLock) backgroundedAt = SystemClock.elapsedRealtime()
    }

    fun onStart() {
        val since = backgroundedAt
        backgroundedAt = null
        suppressLock = false
        if (since != null && lockActive && !locked) {
            val away = SystemClock.elapsedRealtime() - since
            if (away >= settings.lockDelaySeconds * 1000L) lock()
        }
        Clipboard.clearIfExpired(getApplication())
    }

    private fun load() {
        viewModelScope.launch {
            try {
                val data = withContext(ioSerial) { store.load() }
                // Accounts saved before 2.0 have no id; logins link to accounts by id.
                val fixed = Merge.ensureIds(data.accounts, data.logins)
                entries = fixed.accounts.map { Entry(nextId++, it) }
                logins = fixed.logins
                vaultError = null
                loaded = true
                if (fixed.changed) save()
                pendingLink?.let {
                    pendingLink = null
                    openLink(it)
                }
            } catch (e: Exception) {
                vaultError = e.message ?: e.toString()
            }
        }
    }

    /** Deletes unreadable data so the app can be used again (after confirmation). */
    fun resetVault() {
        viewModelScope.launch {
            withContext(ioSerial) { store.destroy() }
            entries = emptyList()
            logins = emptyList()
            vaultError = null
            loaded = true
        }
    }

    fun updateSettings(new: AppSettings) {
        settings = new
        settingsStore.save(new)
    }

    // ---------------------------------------------------------------- accounts

    private fun save() {
        val snapshot = entries.map { it.account }
        val loginSnapshot = logins
        viewModelScope.launch {
            try {
                withContext(ioSerial) { store.save(snapshot, loginSnapshot) }
            } catch (e: Exception) {
                message("Could not save: ${e.message}")
            }
        }
    }

    /** Adds accounts (skipping duplicates) and returns a summary for the user. */
    fun addAccounts(accounts: List<Account>, skipped: List<String> = emptyList()): String {
        if (!loaded) return "Unlock the app first."
        var added = 0
        var duplicates = 0
        val current = entries.toMutableList()
        for (account in accounts) {
            if (current.any { it.account.sameAs(account) }) {
                duplicates++
            } else {
                val id = if (account.id.isEmpty() || current.any { it.account.id == account.id }) Merge.newId() else account.id
                current.add(Entry(nextId++, account.copy(id = id)))
                added++
            }
        }
        if (added > 0) {
            entries = current
            save()
        }
        val summary = when {
            added == 0 && duplicates == 0 -> "Nothing to add."
            added == 0 -> if (duplicates == 1) "This account is already in the list." else "All $duplicates accounts are already in the list."
            duplicates == 0 -> "Added ${plural(added, "account")}."
            else -> "Added ${plural(added, "account")} ($duplicates already in the list)."
        }
        return if (skipped.isEmpty()) summary else summary + skipped.joinToString("") { "\nSkipped $it" }
    }

    fun rename(id: Long, issuer: String, name: String) {
        entries = entries.map {
            if (it.id == id) it.copy(account = it.account.copy(issuer = issuer.trim().take(256), name = name.trim().take(256))) else it
        }
        save()
    }

    fun delete(id: Long) {
        val accountId = entries.firstOrNull { it.id == id }?.account?.id ?: return
        entries = entries.filterNot { it.id == id }
        // Logins that used this 2FA code keep their password but lose the link.
        logins = logins.map { if (it.otp == accountId) it.copy(otp = "") else it }
        save()
        message("Account deleted.")
    }

    fun account(id: String): Account? = if (id.isEmpty()) null else entries.firstOrNull { it.account.id == id }?.account

    // ---------------------------------------------------------------- logins

    fun login(id: String): Login? = logins.firstOrNull { it.id == id }

    /** Adds or updates a login; returns an error to show, or null when it was saved. */
    fun saveLogin(edited: Login): String? {
        if (!loaded) return "Unlock the app first."
        val now = Otp.nowSeconds()
        var login = edited.copy(
            title = edited.title.trim(),
            username = edited.username.trim(),
            url = edited.url.trim(),
            otp = if (account(edited.otp) != null) edited.otp else "",
        )
        login.validationError()?.let { return it }
        val existing = logins.indexOfFirst { it.id == login.id }
        if (existing >= 0) {
            login = login.copy(created = logins[existing].created, modified = now)
            logins = logins.toMutableList().also { it[existing] = login }
        } else {
            login = login.copy(id = Merge.newId(), created = now, modified = now)
            logins = logins + login
        }
        save()
        return null
    }

    fun deleteLogin(id: String) {
        logins = logins.filterNot { it.id == id }
        save()
        message("Password deleted.")
    }

    fun nextHotp(id: Long) {
        entries = entries.map { if (it.id == id) it.copy(account = it.account.copy(counter = it.account.counter + 1)) else it }
        save()
    }

    fun move(id: Long, offset: Int) {
        val list = entries.toMutableList()
        val from = list.indexOfFirst { it.id == id }
        val to = from + offset
        if (from < 0 || to !in list.indices) return
        list.add(to, list.removeAt(from))
        entries = list
        save()
    }

    // ---------------------------------------------------------------- import

    /** Handles the text of a scanned QR code (camera or image). */
    fun importText(text: String): ScanOutcome {
        val result = try {
            ImportParser.parse(text)
        } catch (e: OtpException) {
            return ScanOutcome.Error(e.message ?: "Not an authenticator QR code")
        }
        val summary = addAccounts(result.accounts, result.skipped)
        val batch = result.batch
        if (batch != null && batch.size > 1) {
            val seen = seenBatches.getOrPut(batch.id) { mutableSetOf() }
            seen.add(batch.index)
            if (seen.size < batch.size) {
                return ScanOutcome.Continue("$summary\nGoogle Authenticator code ${seen.size} of ${batch.size} done. Scan the next one.")
            }
            seenBatches.remove(batch.id)
            return ScanOutcome.Done("$summary All ${batch.size} QR codes imported.")
        }
        return ScanOutcome.Done(summary)
    }

    /** `otpauth://` link opened from a website. */
    fun openLink(link: String) {
        if (!loaded) {
            pendingLink = link
            return
        }
        message(importText(link).message)
    }

    fun importImage(uri: Uri) {
        val resolver = getApplication<Application>().contentResolver
        busy = "Looking for a QR code…"
        viewModelScope.launch {
            val texts = withContext(Dispatchers.Default) {
                runCatching { QrCodes.decodeImage(resolver, uri) }
            }
            busy = null
            texts.onFailure { message("Could not read the image: ${it.message}") }
            val found = texts.getOrNull() ?: return@launch
            if (found.isEmpty()) {
                message("No QR code found in this image. Make sure the whole code is visible.")
                return@launch
            }
            val outcomes = found.map(::importText)
            val text = outcomes.joinToString("\n") { it.message }
            message(text)
            if (outcomes.none { it !is ScanOutcome.Error }) return@launch
            if (screen != Screen.Home && outcomes.none { it is ScanOutcome.Continue }) screen = Screen.Home
        }
    }

    fun readBackup(uri: Uri) {
        val resolver = getApplication<Application>().contentResolver
        viewModelScope.launch {
            val bytes = withContext(Dispatchers.IO) {
                runCatching {
                    resolver.openInputStream(uri)?.use { input ->
                        val data = input.readNBytesCompat(MAX_BACKUP_BYTES + 1)
                        require(data.size <= MAX_BACKUP_BYTES) { "This file is too large to be a backup." }
                        data
                    } ?: error("Could not open the file.")
                }
            }
            bytes.onSuccess { pendingBackup = it }.onFailure { message(it.message ?: "Could not read the file.") }
        }
    }

    fun restoreBackup(password: String) {
        val bytes = pendingBackup ?: return
        busy = "Decrypting backup…"
        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) { runCatching { Backup.open(bytes, password) } }
            busy = null
            result.onSuccess { restored ->
                pendingBackup = null
                if (!loaded) return@onSuccess
                var text = if (restored.accounts.isEmpty() && restored.logins.isEmpty()) {
                    "The backup is empty."
                } else {
                    mergeIn(restored.accounts, restored.logins)
                }
                if (restored.invalidEntries > 0) text += "\nSkipped ${plural(restored.invalidEntries, "entry")} that could not be read."
                message(text)
                screen = Screen.Home
            }.onFailure { e ->
                if (e is Backup.BackupException && e.failure == Backup.Failure.WRONG_PASSWORD) {
                    message("Wrong password for this backup.")
                } else {
                    pendingBackup = null
                    message(e.message ?: "Could not restore the backup.")
                }
            }
        }
    }

    /** Adds accounts and logins from a backup (same rules as the Windows app). */
    private fun mergeIn(newAccounts: List<Account>, newLogins: List<Login>): String {
        val merged = Merge.merge(entries.map { it.account }, logins, newAccounts, newLogins)
        val known = entries.associateBy { it.account.id }
        entries = merged.accounts.map { account -> known[account.id]?.copy(account = account) ?: Entry(nextId++, account) }
        logins = merged.logins
        save()
        return merged.report.summary()
    }

    // ---------------------------------------------------------------- export

    /** Opens the export screen with everything chosen. */
    fun openExport() {
        exportSelection = ExportSelection(entries.map { it.account.id }.toSet(), logins.map { it.id }.toSet())
        screen = Screen.Export
    }

    private fun selectedAccounts() = entries.map { it.account }.filter { it.id in exportSelection.accounts }

    private fun selectedLogins() = logins.filter { it.id in exportSelection.logins }

    /** One account as a standard otpauth:// QR code, which any authenticator app can scan. */
    fun showAccountQr(entry: Entry) {
        val account = entries.firstOrNull { it.id == entry.id }?.account ?: return
        var note = account.displayTitle
        if (!Migration.exportable(account) || account.type == OtpType.HOTP) {
            note += " · uses settings some apps (like Google Authenticator) may not support"
        }
        screen = Screen.ExportQr(listOf(account.toOtpAuth()), note, single = true)
    }

    fun showExportQr() {
        val all = selectedAccounts()
        if (all.isEmpty()) {
            message("Choose at least one 2FA code to export.")
            return
        }
        val exportable = all.filter(Migration::exportable)
        if (exportable.isEmpty()) {
            message("Google Authenticator only supports 30-second codes with 6 or 8 digits. Use an encrypted backup file instead.")
            return
        }
        val batchId = SecureRandom().nextInt() and 0x7fffffff
        val uris = Migration.encodeUris(exportable, batchId)
        val leftOut = all.size - exportable.size
        var note = "${plural(exportable.size, "account")} in ${plural(uris.size, "QR code")}."
        if (leftOut > 0) note += " ${plural(leftOut, "account")} left out (not supported by Google Authenticator) — use a backup file for those."
        screen = Screen.ExportQr(uris, note)
    }

    fun writeBackup(uri: Uri) {
        val password = pendingExportPassword ?: return
        pendingExportPassword = null
        val accounts = selectedAccounts()
        val chosenLogins = selectedLogins()
        val resolver = getApplication<Application>().contentResolver
        busy = "Encrypting backup…"
        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                runCatching {
                    val contents = Backup.create(accounts, password, logins = chosenLogins)
                    withContext(Dispatchers.IO) {
                        resolver.openOutputStream(uri, "wt")?.use { it.write(contents.toByteArray(Charsets.UTF_8)) }
                            ?: error("Could not open the file for writing.")
                    }
                }
            }
            busy = null
            result.onSuccess {
                val what = buildList {
                    if (accounts.isNotEmpty()) add(plural(accounts.size, "2FA code"))
                    if (chosenLogins.isNotEmpty()) add(plural(chosenLogins.size, "password"))
                }
                message("Backup of ${what.joinToString(" and ")} saved.")
            }
                .onFailure { message("Could not save the backup: ${it.message}") }
        }
    }
}

fun plural(n: Int, word: String) = if (n == 1) "1 $word" else "$n ${word}s"

private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(16 * 1024)
    while (out.size() < limit) {
        val n = read(buffer, 0, minOf(buffer.size, limit - out.size()))
        if (n < 0) break
        out.write(buffer, 0, n)
    }
    return out.toByteArray()
}
