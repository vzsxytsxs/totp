package app.authenticator.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.authenticator.Entry
import app.authenticator.ExportSelection
import app.authenticator.core.Account
import app.authenticator.core.GeneratorOptions
import app.authenticator.core.Login
import app.authenticator.core.Otp
import app.authenticator.core.OtpType
import app.authenticator.core.PasswordGenerator
import kotlinx.coroutines.delay
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** What to copy from a saved login. */
enum class LoginField(val label: String) {
    Username("User name"),
    Password("Password"),
    Otp("2FA code"),
}

private val avatarColors = listOf(
    Color(0xFF2563EB), Color(0xFF7C3AED), Color(0xFFDB2777), Color(0xFFDC2626),
    Color(0xFFEA580C), Color(0xFF16A34A), Color(0xFF0D9488), Color(0xFF0891B2),
)

@Composable
private fun Avatar(text: String) {
    val letter = text.trim().firstOrNull { it.isLetterOrDigit() }?.uppercaseChar() ?: '?'
    val color = avatarColors[Math.floorMod(text.lowercase().hashCode(), avatarColors.size)]
    Box(Modifier.size(40.dp).background(color, CircleShape), contentAlignment = Alignment.Center) {
        Text(letter.toString(), color = Color.White, style = MaterialTheme.typography.titleMedium)
    }
}

/** Saved logins on the Passwords tab of the home screen. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PasswordList(
    logins: List<Login>,
    linked: (Login) -> Account?,
    contentPadding: PaddingValues,
    onOpen: (Login) -> Unit,
    onCopy: (Login, LoginField) -> Unit,
) {
    LazyColumn(modifier = Modifier.fillMaxSize(), contentPadding = contentPadding) {
        items(logins, key = { it.id }) { login ->
            var menu by remember { mutableStateOf(false) }
            val account = linked(login)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .combinedClickable(onClick = { onOpen(login) }, onLongClick = { menu = true })
                    .padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Avatar(login.displayTitle)
                Spacer(Modifier.size(16.dp))
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            login.displayTitle,
                            style = MaterialTheme.typography.titleSmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false),
                        )
                        if (account != null) {
                            Spacer(Modifier.size(6.dp))
                            Text(
                                "2FA",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier
                                    .background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(4.dp))
                                    .padding(horizontal = 4.dp, vertical = 1.dp),
                            )
                        }
                    }
                    val subtitle = login.username.ifEmpty { login.host }
                    if (subtitle.isNotEmpty()) {
                        Text(
                            subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                IconButton(onClick = { onCopy(login, LoginField.Password) }, enabled = login.password.isNotEmpty()) {
                    Icon(AppIcons.Copy, contentDescription = "Copy password")
                }
                Box {
                    IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        if (login.username.isNotEmpty()) {
                            DropdownMenuItem(text = { Text("Copy user name") }, onClick = { menu = false; onCopy(login, LoginField.Username) })
                        }
                        if (login.password.isNotEmpty()) {
                            DropdownMenuItem(text = { Text("Copy password") }, onClick = { menu = false; onCopy(login, LoginField.Password) })
                        }
                        if (account != null) {
                            DropdownMenuItem(text = { Text("Copy 2FA code") }, onClick = { menu = false; onCopy(login, LoginField.Otp) })
                        }
                        DropdownMenuItem(text = { Text("Open / edit") }, onClick = { menu = false; onOpen(login) })
                    }
                }
            }
            HorizontalDivider(modifier = Modifier.padding(start = 72.dp, end = 16.dp))
        }
        item {
            Text(
                "Tap to open · copy button copies the password",
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun PasswordsEmptyState(modifier: Modifier, onAdd: () -> Unit) {
    Column(
        modifier = modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(AppIcons.Key, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(64.dp))
        Spacer(Modifier.size(16.dp))
        Text("No passwords yet", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.size(8.dp))
        Text(
            "Save the logins of your websites here, or bring them from the Windows app with a backup file (menu → Restore backup file).",
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.size(24.dp))
        Button(onClick = onAdd) { Text("Add password") }
    }
}

private fun formatDate(seconds: Long): String =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
        .format(Instant.ofEpochSecond(seconds).atZone(ZoneId.systemDefault()))

/** Opening a website in the browser; adds https:// when the address has no scheme. */
private fun websiteUri(url: String): String? {
    val t = url.trim()
    if (t.isEmpty() || t.any { it.isWhitespace() }) return null
    val withScheme = if (t.contains("://")) t else "https://$t"
    return withScheme.takeIf { it.startsWith("https://", true) || it.startsWith("http://", true) }
}

/**
 * Shows and edits one saved login ([login] null: a new one). [onSave] returns
 * an error to show, or null when it was saved.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(
    login: Login?,
    entries: List<Entry>,
    snackbar: SnackbarHostState,
    onSave: (Login) -> String?,
    onDelete: () -> Unit,
    onCopy: (String, LoginField) -> Unit,
    onBack: () -> Unit,
) {
    val original = login ?: Login()
    var title by rememberSaveable { mutableStateOf(original.title) }
    var url by rememberSaveable { mutableStateOf(original.url) }
    var username by rememberSaveable { mutableStateOf(original.username) }
    var password by rememberSaveable { mutableStateOf(original.password) }
    var notes by rememberSaveable { mutableStateOf(original.notes) }
    var otp by rememberSaveable { mutableStateOf(original.otp) }
    var reveal by rememberSaveable { mutableStateOf(login == null) }
    var error by remember { mutableStateOf<String?>(null) }
    var menu by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmDiscard by remember { mutableStateOf(false) }
    var generator by remember { mutableStateOf(false) }
    var picker by remember { mutableStateOf(false) }
    var generatorOptions by remember { mutableStateOf(GeneratorOptions()) }
    val uriHandler = LocalUriHandler.current

    val edited = original.copy(title = title, url = url, username = username, password = password, notes = notes, otp = otp)
    val changed = edited != original
    val leave: () -> Unit = {
        if (changed) {
            confirmDiscard = true
        } else {
            onBack()
        }
    }
    BackHandler(onBack = leave)

    val linked = entries.firstOrNull { otp.isNotEmpty() && it.account.id == otp }?.account

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (login == null) "New password" else "Password", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = { IconButton(onClick = leave) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
                actions = {
                    IconButton(onClick = { error = onSave(edited) }, enabled = login == null || changed) {
                        Icon(Icons.Default.Check, contentDescription = "Save")
                    }
                    if (login != null) {
                        Box {
                            IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More") }
                            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                                DropdownMenuItem(
                                    text = { Text("Delete password…", color = MaterialTheme.colorScheme.error) },
                                    onClick = { menu = false; confirmDelete = true },
                                )
                            }
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                title,
                { title = it },
                label = { Text("Title") },
                placeholder = { Text(Login(url = url).displayTitle.ifEmpty { "For example: GitHub" }) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                url,
                { url = it },
                label = { Text("Website") },
                placeholder = { Text("https://example.com") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                trailingIcon = {
                    val uri = websiteUri(url)
                    if (uri != null) {
                        IconButton(onClick = { runCatching { uriHandler.openUri(uri) } }) {
                            Icon(AppIcons.OpenInNew, contentDescription = "Open website")
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                username,
                { username = it },
                label = { Text("User name or email") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                trailingIcon = {
                    if (username.isNotEmpty()) {
                        IconButton(onClick = { onCopy(username, LoginField.Username) }) {
                            Icon(AppIcons.Copy, contentDescription = "Copy user name")
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                password,
                { password = it },
                label = { Text("Password") },
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                visualTransformation = if (reveal) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                trailingIcon = {
                    Row {
                        IconButton(onClick = { reveal = !reveal }) {
                            Icon(
                                if (reveal) AppIcons.VisibilityOff else AppIcons.Visibility,
                                contentDescription = if (reveal) "Hide password" else "Show password",
                            )
                        }
                        if (password.isNotEmpty()) {
                            IconButton(onClick = { onCopy(password, LoginField.Password) }) {
                                Icon(AppIcons.Copy, contentDescription = "Copy password")
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            TextButton(onClick = { generator = true }) {
                Icon(AppIcons.Dice, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text("Generate a password")
            }

            LinkedCode(
                account = linked,
                onChoose = { picker = true },
                onCopy = { code -> onCopy(code, LoginField.Otp) },
            )

            OutlinedTextField(
                notes,
                { notes = it },
                label = { Text("Notes") },
                minLines = 3,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                modifier = Modifier.fillMaxWidth(),
            )
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (login != null && login.modified > 0) {
                Text(
                    "Changed ${formatDate(login.modified)} · added ${formatDate(login.created)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Button(
                onClick = { error = onSave(edited) },
                enabled = login == null || changed,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Save") }
        }
    }

    if (generator) {
        GeneratorDialog(
            options = generatorOptions,
            onOptions = { generatorOptions = it },
            onUse = { password = it; reveal = true; generator = false },
            onDismiss = { generator = false },
        )
    }
    if (picker) {
        AccountPickerDialog(
            entries = entries,
            selected = otp,
            onPick = { otp = it; picker = false },
            onDismiss = { picker = false },
        )
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete password?") },
            text = { Text("\"${original.displayTitle}\" will be removed from this phone. Its 2FA code (if any) is kept.") },
            confirmButton = {
                TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text("Discard changes?") },
            text = { Text("The changes you made to this password are not saved.") },
            confirmButton = { TextButton(onClick = { confirmDiscard = false; onBack() }) { Text("Discard") } },
            dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") } },
        )
    }
}

/** The 2FA code linked to a login: shows the current code, lets the user change the link. */
@Composable
private fun LinkedCode(account: Account?, onChoose: () -> Unit, onCopy: (String) -> Unit) {
    var now by remember { mutableLongStateOf(Otp.nowSeconds()) }
    LaunchedEffect(account != null) {
        while (account != null) {
            delay(1000 - System.currentTimeMillis() % 1000 + 5)
            now = Otp.nowSeconds()
        }
    }
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.clickable(onClick = onChoose).padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp).heightIn(min = 48.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("2FA code", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (account == null) {
                    Text("None · tap to link one of your codes", style = MaterialTheme.typography.bodyMedium)
                } else {
                    val totp = account.type == OtpType.TOTP
                    val window = if (totp) now / account.period.coerceAtLeast(1) else account.counter
                    val code = remember(account, window) { account.codeAt(now) }
                    Text(account.displayTitle, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            formatCode(code),
                            style = MaterialTheme.typography.titleLarge,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        if (totp) {
                            Spacer(Modifier.size(8.dp))
                            Text(
                                "${account.secondsRemaining(now)} s",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
            if (account != null) {
                IconButton(onClick = { onCopy(account.codeAt(Otp.nowSeconds())) }) {
                    Icon(AppIcons.Copy, contentDescription = "Copy 2FA code")
                }
            }
        }
    }
}

@Composable
private fun AccountPickerDialog(entries: List<Entry>, selected: String, onPick: (String) -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("2FA code for this login") },
        text = {
            Column(Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState())) {
                PickRow("None", "", selected == "") { onPick("") }
                entries.forEach { entry ->
                    val account = entry.account
                    val title = account.issuer.ifEmpty { account.displayTitle }
                    val subtitle = if (account.issuer.isNotEmpty()) account.name else ""
                    PickRow(title, subtitle, account.id == selected) { onPick(account.id) }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PickRow(title: String, subtitle: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().selectable(selected = selected, role = Role.RadioButton, onClick = onClick).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Spacer(Modifier.size(12.dp))
        Column {
            Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (subtitle.isNotEmpty()) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
            }
        }
    }
}

@Composable
private fun GeneratorDialog(
    options: GeneratorOptions,
    onOptions: (GeneratorOptions) -> Unit,
    onUse: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var value by remember { mutableStateOf(PasswordGenerator.generate(options)) }
    val update: (GeneratorOptions) -> Unit = { new ->
        onOptions(new)
        value = PasswordGenerator.generate(new)
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generate a password") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Surface(shape = RoundedCornerShape(8.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
                    Row(Modifier.fillMaxWidth().padding(start = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(value, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f).padding(vertical = 8.dp))
                        IconButton(onClick = { value = PasswordGenerator.generate(options) }) {
                            Icon(AppIcons.Dice, contentDescription = "Another password")
                        }
                    }
                }
                Spacer(Modifier.size(4.dp))
                Text("Length: ${options.length}", style = MaterialTheme.typography.labelLarge)
                Slider(
                    value = options.length.toFloat(),
                    onValueChange = { if (it.toInt() != options.length) update(options.copy(length = it.toInt())) },
                    valueRange = 8f..64f,
                )
                GeneratorOption("Capital letters (A-Z)", options.uppercase) { update(options.copy(uppercase = it)) }
                GeneratorOption("Small letters (a-z)", options.lowercase) { update(options.copy(lowercase = it)) }
                GeneratorOption("Digits (0-9)", options.digits) { update(options.copy(digits = it)) }
                GeneratorOption("Symbols (!@#…)", options.symbols) { update(options.copy(symbols = it)) }
                GeneratorOption("Avoid look-alikes (I l 1 O 0)", options.avoidSimilar) { update(options.copy(avoidSimilar = it)) }
            }
        },
        confirmButton = { TextButton(onClick = { onUse(value) }) { Text("Use this password") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun GeneratorOption(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().toggleable(value = checked, role = Role.Checkbox, onValueChange = onChange),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = null)
        Spacer(Modifier.size(8.dp))
        Text(label)
    }
}

/** Choosing which 2FA codes and passwords go into an export. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportChooseScreen(
    entries: List<Entry>,
    logins: List<Login>,
    selection: ExportSelection,
    onChange: (ExportSelection) -> Unit,
    onDone: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Choose what to export") },
                navigationIcon = { IconButton(onClick = onDone) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
                actions = { TextButton(onClick = onDone) { Text("Done") } },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
            item {
                SectionHeader(
                    "2FA codes (${selection.accounts.size} of ${entries.size})",
                    onAll = { onChange(selection.copy(accounts = entries.map { it.account.id }.toSet())) },
                    onNone = { onChange(selection.copy(accounts = emptySet())) },
                )
            }
            items(entries, key = { "a" + it.id }) { entry ->
                val account = entry.account
                val checked = account.id in selection.accounts
                ChoiceRow(
                    title = account.issuer.ifEmpty { account.displayTitle },
                    subtitle = if (account.issuer.isNotEmpty()) account.name else "",
                    checked = checked,
                ) {
                    onChange(selection.copy(accounts = if (checked) selection.accounts - account.id else selection.accounts + account.id))
                }
            }
            if (logins.isNotEmpty()) {
                item {
                    SectionHeader(
                        "Passwords (${selection.logins.size} of ${logins.size}) · backup file only",
                        onAll = { onChange(selection.copy(logins = logins.map { it.id }.toSet())) },
                        onNone = { onChange(selection.copy(logins = emptySet())) },
                    )
                }
                items(logins, key = { "l" + it.id }) { login ->
                    val checked = login.id in selection.logins
                    ChoiceRow(title = login.displayTitle, subtitle = login.username, checked = checked) {
                        onChange(selection.copy(logins = if (checked) selection.logins - login.id else selection.logins + login.id))
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String, onAll: () -> Unit, onNone: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary, modifier = Modifier.weight(1f))
        TextButton(onClick = onAll) { Text("All") }
        TextButton(onClick = onNone) { Text("None") }
    }
}

@Composable
private fun ChoiceRow(title: String, subtitle: String, checked: Boolean, onToggle: () -> Unit) {
    ListItem(
        headlineContent = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = subtitle.takeIf { it.isNotEmpty() }?.let { text ->
            @Composable { Text(text, maxLines = 1, overflow = TextOverflow.Ellipsis) }
        },
        leadingContent = { Checkbox(checked = checked, onCheckedChange = null) },
        modifier = Modifier.toggleable(value = checked, role = Role.Checkbox, onValueChange = { onToggle() }),
    )
}
