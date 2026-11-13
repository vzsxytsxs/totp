package app.authenticator

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.authenticator.ui.AuthenticatorTheme
import app.authenticator.ui.BackupPasswordDialog
import app.authenticator.ui.BusyOverlay
import app.authenticator.ui.EditDialog
import app.authenticator.ui.ExportChooseScreen
import app.authenticator.ui.ExportQrScreen
import app.authenticator.ui.ExportScreen
import app.authenticator.ui.HomeScreen
import app.authenticator.ui.LockScreen
import app.authenticator.ui.LoginField
import app.authenticator.ui.LoginScreen
import app.authenticator.ui.ManualEntryScreen
import app.authenticator.ui.ScannerScreen
import app.authenticator.ui.SettingsScreen
import app.authenticator.ui.VaultErrorScreen
import app.authenticator.core.Otp

class MainActivity : FragmentActivity() {
    private val vm: AppViewModel by viewModels()
    private var authenticating = false

    private val pickImageLauncher = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        vm.suppressLock = false
        if (uri != null) vm.importImage(uri)
    }
    private val createBackupLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        vm.suppressLock = false
        if (uri != null) vm.writeBackup(uri) else vm.pendingExportPassword = null
    }
    private val openBackupLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        vm.suppressLock = false
        if (uri != null) vm.readBackup(uri)
    }
    private val cameraPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        vm.suppressLock = false
        if (granted) {
            vm.scanStatus = null
            vm.screen = Screen.Scanner
        } else {
            vm.message("Camera access is needed to scan QR codes. You can also scan a screenshot instead.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        applyScreenshotSetting()
        if (savedInstanceState == null) handleLink(intent)
        setContent {
            AuthenticatorTheme {
                Surface {
                    App()
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLink(intent)
    }

    override fun onStart() {
        super.onStart()
        vm.onStart()
    }

    override fun onStop() {
        super.onStop()
        // Rotating the screen recreates the activity; that is not leaving the app.
        if (!isChangingConfigurations) vm.onStop()
    }

    private fun handleLink(intent: Intent?) {
        val data = intent?.data?.toString() ?: return
        if (data.startsWith("otpauth", ignoreCase = true)) vm.openLink(data)
    }

    private fun applyScreenshotSetting() {
        if (vm.settings.blockScreenshots) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    /** Fingerprint/face, falling back to the phone's PIN, pattern or password. */
    private fun authenticate(title: String, onSuccess: () -> Unit) {
        if (!vm.canAuthenticate()) {
            onSuccess()
            return
        }
        if (authenticating) return
        authenticating = true
        vm.suppressLock = true
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    authenticating = false
                    vm.suppressLock = false
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    authenticating = false
                    vm.suppressLock = false
                    val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    if (!cancelled) vm.message(errString.toString())
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Use your fingerprint, face or screen lock")
            .setAllowedAuthenticators(BIOMETRIC_WEAK or DEVICE_CREDENTIAL)
            .build()
        prompt.authenticate(info)
    }

    private fun openScanner() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            vm.scanStatus = null
            vm.screen = Screen.Scanner
        } else {
            vm.suppressLock = true
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun pickImage() {
        vm.suppressLock = true
        pickImageLauncher.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
    }

    private fun copy(text: String, what: String) {
        if (text.isEmpty()) return
        Clipboard.copy(this, text, vm.settings.clearClipboard)
        if (!Clipboard.systemShowsConfirmation) vm.message("$what copied.")
    }

    private fun copyFromLogin(login: app.authenticator.core.Login, field: LoginField) {
        val text = when (field) {
            LoginField.Username -> login.username
            LoginField.Password -> login.password
            LoginField.Otp -> vm.account(login.otp)?.codeAt(Otp.nowSeconds()) ?: ""
        }
        copy(text, field.label)
    }

    private fun openBackupFile() {
        vm.suppressLock = true
        openBackupLauncher.launch(arrayOf("application/json", "application/octet-stream", "text/plain", "*/*"))
    }

    @Composable
    private fun App() {
        val snackbar = remember { SnackbarHostState() }
        var editing by remember { mutableStateOf<Entry?>(null) }

        LaunchedEffect(Unit) {
            for (text in vm.messages) {
                snackbar.currentSnackbarData?.dismiss()
                snackbar.showSnackbar(text)
            }
        }
        LaunchedEffect(vm.settings.blockScreenshots) { applyScreenshotSetting() }

        val error = vm.vaultError
        when {
            vm.locked -> LockScreen(snackbar, onUnlock = { authenticate("Unlock Authenticator") { vm.unlocked() } })
            error != null -> VaultErrorScreen(error, onReset = vm::resetVault)
            !vm.loaded -> Box(Modifier.fillMaxSize())
            else -> Screens(snackbar, onEdit = { editing = it })
        }

        editing?.let { entry ->
            EditDialog(
                entry = entry,
                onSave = { issuer, name -> vm.rename(entry.id, issuer, name); editing = null },
                onDelete = { vm.delete(entry.id); editing = null },
                onMove = { vm.move(entry.id, it) },
                onShowQr = {
                    editing = null
                    authenticate("Show QR code") { vm.showAccountQr(entry) }
                },
                onDismiss = { editing = null },
            )
        }
        LaunchedEffect(vm.locked) { if (vm.locked) editing = null }
        if (vm.pendingBackup != null && !vm.locked) {
            BackupPasswordDialog(onRestore = vm::restoreBackup, onDismiss = { vm.pendingBackup = null })
        }
        vm.busy?.let { BusyOverlay(it) }
    }

    @Composable
    private fun Screens(snackbar: SnackbarHostState, onEdit: (Entry) -> Unit) {
        val goHome = { vm.screen = Screen.Home }
        if (vm.screen != Screen.Home) {
            BackHandler {
                vm.screen = when (val current = vm.screen) {
                    is Screen.ExportQr -> if (current.single) Screen.Home else Screen.Export
                    Screen.ExportChoose -> Screen.Export
                    else -> Screen.Home
                }
            }
        }
        when (val screen = vm.screen) {
            Screen.Home -> HomeScreen(
                tab = vm.homeTab,
                onTab = { vm.homeTab = it },
                entries = vm.entries,
                logins = vm.logins,
                linked = { vm.account(it.otp) },
                lockAvailable = vm.lockActive,
                snackbar = snackbar,
                onCopy = { entry -> copy(entry.account.codeAt(Otp.nowSeconds()), "Code") },
                onNextHotp = { vm.nextHotp(it.id) },
                onEdit = onEdit,
                onOpenLogin = { vm.screen = Screen.LoginEdit(it.id) },
                onAddLogin = { vm.screen = Screen.LoginEdit(null) },
                onCopyLogin = ::copyFromLogin,
                onScan = ::openScanner,
                onPickImage = ::pickImage,
                onManual = { vm.screen = Screen.Manual },
                onRestore = ::openBackupFile,
                onExport = vm::openExport,
                onSettings = { vm.screen = Screen.Settings },
                onLock = vm::lock,
            )
            Screen.Scanner -> ScannerScreen(
                status = vm.scanStatus,
                onCode = { text ->
                    val outcome = vm.importText(text)
                    if (outcome is ScanOutcome.Done) {
                        vm.screen = Screen.Home
                        vm.message(outcome.message)
                    } else {
                        vm.scanStatus = outcome.message
                    }
                    outcome
                },
                onPickImage = ::pickImage,
                onClose = goHome,
            )
            Screen.Manual -> ManualEntryScreen(
                snackbar = snackbar,
                onAdd = { account ->
                    val result = vm.addAccounts(listOf(account))
                    vm.message(result)
                    vm.screen = Screen.Home
                },
                onLink = { link ->
                    val outcome = vm.importText(link)
                    vm.message(outcome.message)
                    if (outcome !is ScanOutcome.Error) vm.screen = Screen.Home
                },
                onBack = goHome,
            )
            Screen.Export -> ExportScreen(
                accounts = vm.exportSelection.accounts.size,
                accountsTotal = vm.entries.size,
                logins = vm.exportSelection.logins.size,
                loginsTotal = vm.logins.size,
                snackbar = snackbar,
                onChoose = { vm.screen = Screen.ExportChoose },
                onShowQr = { authenticate("Show export codes") { vm.showExportQr() } },
                onSaveBackup = { password ->
                    authenticate("Create backup") {
                        vm.pendingExportPassword = password
                        vm.suppressLock = true
                        createBackupLauncher.launch("authenticator-backup-${java.time.LocalDate.now()}.json")
                    }
                },
                onBack = goHome,
            )
            Screen.ExportChoose -> ExportChooseScreen(
                entries = vm.entries,
                logins = vm.logins,
                selection = vm.exportSelection,
                onChange = { vm.exportSelection = it },
                onDone = { vm.screen = Screen.Export },
            )
            is Screen.ExportQr -> ExportQrScreen(
                screen.uris,
                screen.note,
                single = screen.single,
                onDone = { vm.screen = if (screen.single) Screen.Home else Screen.Export },
            )
            is Screen.LoginEdit -> key(screen.id) {
                val login = screen.id?.let(vm::login)
                if (screen.id != null && login == null) {
                    // Deleted (or the vault was locked): nothing to show.
                    LaunchedEffect(Unit) { vm.screen = Screen.Home }
                } else {
                    LoginScreen(
                        login = login,
                        entries = vm.entries,
                        snackbar = snackbar,
                        onSave = { edited ->
                            vm.saveLogin(edited).also { error ->
                                if (error == null) {
                                    vm.screen = Screen.Home
                                    vm.message("Password saved.")
                                }
                            }
                        },
                        onDelete = {
                            vm.screen = Screen.Home
                            screen.id?.let(vm::deleteLogin)
                        },
                        onCopy = { text, field -> copy(text, field.label) },
                        onBack = { vm.screen = Screen.Home },
                    )
                }
            }
            Screen.Settings -> SettingsScreen(
                settings = vm.settings,
                lockAvailable = vm.canAuthenticate(),
                onChange = { new ->
                    // Turning the lock off requires proving it is really you.
                    if (vm.settings.appLock && !new.appLock) {
                        authenticate("Turn off app lock") { vm.updateSettings(new) }
                    } else {
                        vm.updateSettings(new)
                    }
                },
                onBack = goHome,
            )
        }
    }
}
