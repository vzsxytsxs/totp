package app.authenticator.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
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
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.authenticator.Entry
import app.authenticator.core.Otp
import app.authenticator.core.OtpType
import kotlinx.coroutines.delay

fun formatCode(code: String): String = when (code.length) {
    6, 7 -> code.substring(0, 3) + " " + code.substring(3)
    8 -> code.substring(0, 4) + " " + code.substring(4)
    else -> code
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    entries: List<Entry>,
    lockAvailable: Boolean,
    snackbar: SnackbarHostState,
    onCopy: (Entry) -> Unit,
    onNextHotp: (Entry) -> Unit,
    onEdit: (Entry) -> Unit,
    onScan: () -> Unit,
    onPickImage: () -> Unit,
    onManual: () -> Unit,
    onRestore: () -> Unit,
    onExport: () -> Unit,
    onSettings: () -> Unit,
    onLock: () -> Unit,
) {
    var searching by rememberSaveable { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    var menu by remember { mutableStateOf(false) }
    var addSheet by rememberSaveable { mutableStateOf(false) }

    // One tick per second, aligned to the clock; stops when the screen is not shown.
    var now by remember { mutableLongStateOf(Otp.nowSeconds()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000 - System.currentTimeMillis() % 1000 + 5)
            now = Otp.nowSeconds()
        }
    }

    val visible = if (query.isBlank()) entries else entries.filter {
        it.account.issuer.contains(query.trim(), ignoreCase = true) || it.account.name.contains(query.trim(), ignoreCase = true)
    }

    Scaffold(
        topBar = {
            if (searching) {
                val focus = remember { FocusRequester() }
                TopAppBar(
                    title = {
                        TextField(
                            value = query,
                            onValueChange = { query = it },
                            placeholder = { Text("Search") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                                focusedIndicatorColor = Color.Transparent,
                                unfocusedIndicatorColor = Color.Transparent,
                            ),
                            modifier = Modifier.fillMaxWidth().focusRequester(focus),
                        )
                        LaunchedEffect(Unit) { focus.requestFocus() }
                    },
                    actions = {
                        IconButton(onClick = { searching = false; query = "" }) {
                            Icon(Icons.Default.Close, contentDescription = "Close search")
                        }
                    },
                )
            } else {
                TopAppBar(
                    title = { Text("Authenticator") },
                    actions = {
                        if (entries.isNotEmpty()) {
                            IconButton(onClick = { searching = true }) { Icon(Icons.Default.Search, contentDescription = "Search") }
                        }
                        if (lockAvailable) {
                            IconButton(onClick = onLock) { Icon(Icons.Default.Lock, contentDescription = "Lock") }
                        }
                        Box {
                            IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More") }
                            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                                DropdownMenuItem(text = { Text("Export / transfer") }, onClick = { menu = false; onExport() })
                                DropdownMenuItem(text = { Text("Restore backup file") }, onClick = { menu = false; onRestore() })
                                DropdownMenuItem(text = { Text("Settings") }, onClick = { menu = false; onSettings() })
                            }
                        }
                    },
                )
            }
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { addSheet = true }) { Icon(Icons.Default.Add, contentDescription = "Add account") }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        when {
            entries.isEmpty() -> EmptyState(Modifier.padding(padding), onAdd = { addSheet = true })
            visible.isEmpty() -> Text(
                "No accounts match your search.",
                modifier = Modifier.padding(padding).padding(32.dp).fillMaxWidth(),
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            else -> LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(
                    top = padding.calculateTopPadding(),
                    bottom = padding.calculateBottomPadding() + 88.dp,
                ),
            ) {
                items(visible, key = { it.id }) { entry ->
                    EntryRow(entry, now, onCopy = { onCopy(entry) }, onNext = { onNextHotp(entry) }, onEdit = { onEdit(entry) })
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))
                }
                item {
                    Text(
                        "Tap a code to copy it · long-press to edit",
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }

    if (addSheet) {
        ModalBottomSheet(onDismissRequest = { addSheet = false }) {
            Column(Modifier.padding(bottom = 24.dp)) {
                Text(
                    "Add account",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                )
                SheetItem(AppIcons.Camera, "Scan QR code", "From a website, or Google Authenticator's export screen") {
                    addSheet = false; onScan()
                }
                SheetItem(AppIcons.Image, "Scan QR from image", "Screenshot or photo saved on the phone") {
                    addSheet = false; onPickImage()
                }
                SheetItem(AppIcons.Key, "Enter setup key", "Type the secret key or paste an otpauth:// link") {
                    addSheet = false; onManual()
                }
                SheetItem(AppIcons.Restore, "Restore backup file", "Encrypted backup from this app on Android or Windows") {
                    addSheet = false; onRestore()
                }
                Text(
                    "From Google Authenticator: open it → menu → Transfer accounts → Export accounts, then use \"Scan QR code\" here for each code it shows.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp),
                )
            }
        }
    }
}

@Composable
private fun SheetItem(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle) },
        leadingContent = { Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary) },
        modifier = Modifier.combinedClickableCompat(onClick),
    )
}

@OptIn(ExperimentalFoundationApi::class)
private fun Modifier.combinedClickableCompat(onClick: () -> Unit, onLongClick: (() -> Unit)? = null) =
    this.combinedClickable(onClick = onClick, onLongClick = onLongClick)

@Composable
private fun EmptyState(modifier: Modifier, onAdd: () -> Unit) {
    Column(
        modifier = modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(AppIcons.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(64.dp))
        Spacer(Modifier.height(16.dp))
        Text("No accounts yet", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Scan a QR code, enter a setup key, or import everything from Google Authenticator.",
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))
        Button(onClick = onAdd) { Text("Add account") }
    }
}

@Composable
private fun EntryRow(entry: Entry, now: Long, onCopy: () -> Unit, onNext: () -> Unit, onEdit: () -> Unit) {
    val account = entry.account
    val totp = account.type == OtpType.TOTP
    val window = if (totp) now / account.period.coerceAtLeast(1) else account.counter
    val code = remember(account, window) { formatCode(account.codeAt(now)) }
    val remaining = if (totp) account.secondsRemaining(now) else 0
    val warn = totp && remaining <= 5
    val codeColor = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickableCompat(onClick = onCopy, onLongClick = onEdit)
            .padding(start = 16.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            val title = account.issuer.ifEmpty { account.displayTitle }
            Text(title, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (account.issuer.isNotEmpty() && account.name.isNotEmpty()) {
                Text(
                    account.name,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                code,
                fontSize = 32.sp,
                fontWeight = FontWeight.Medium,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp,
                color = codeColor,
            )
        }
        if (totp) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(40.dp)) {
                CircularProgressIndicator(
                    progress = { remaining.toFloat() / account.period.coerceAtLeast(1) },
                    modifier = Modifier.size(32.dp),
                    color = codeColor,
                    strokeWidth = 3.dp,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
                Text("$remaining", style = MaterialTheme.typography.labelSmall, color = codeColor)
            }
        } else {
            IconButton(onClick = onNext) { Icon(Icons.Default.Refresh, contentDescription = "Next code") }
        }
        IconButton(onClick = onEdit) { Icon(Icons.Default.MoreVert, contentDescription = "Edit or delete") }
    }
}
