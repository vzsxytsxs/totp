package app.authenticator.ui

import android.util.Size
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import app.authenticator.QrCodes
import app.authenticator.ScanOutcome
import app.authenticator.core.Account
import app.authenticator.core.Base32
import app.authenticator.core.HashAlgorithm
import app.authenticator.core.OtpException
import app.authenticator.core.OtpType
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors

/**
 * Live camera preview that decodes QR codes. [onCode] runs on the main thread and
 * returns what happened, so multi-code Google Authenticator exports keep scanning.
 */
@Composable
fun ScannerScreen(
    status: String?,
    onCode: (String) -> ScanOutcome,
    onPickImage: () -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val handleCode by rememberUpdatedState(onCode)
    val previewView = remember { PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER } }
    var cameraError by remember { mutableStateOf<String?>(null) }

    DisposableEffect(lifecycleOwner) {
        val executor = Executors.newSingleThreadExecutor()
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val providerFuture = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        var lastText: String? = null
        var lastTime = 0L
        var finished = false
        providerFuture.addListener({
            val cameraProvider = providerFuture.get()
            provider = cameraProvider
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(
                    ResolutionSelector.Builder()
                        .setResolutionStrategy(
                            ResolutionStrategy(Size(1920, 1080), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER),
                        )
                        .build(),
                )
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            val reader = QRCodeReader()
            analysis.setAnalyzer(executor) { image ->
                val text = try {
                    QrCodes.decodeFrame(image, reader)
                } finally {
                    image.close()
                }
                if (text != null) {
                    mainExecutor.execute {
                        val now = System.currentTimeMillis()
                        // The same code stays in view for many frames: handle it once.
                        if (finished || (text == lastText && now - lastTime < 3000)) return@execute
                        lastText = text
                        lastTime = now
                        if (handleCode(text) is ScanOutcome.Done) finished = true
                    }
                }
            }
            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                cameraError = "The camera could not be started: ${e.message ?: e.javaClass.simpleName}"
            }
        }, mainExecutor)
        onDispose {
            provider?.unbindAll()
            executor.shutdown()
        }
    }

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())
        Box(
            Modifier
                .align(Alignment.Center)
                .size(260.dp)
                .border(3.dp, Color.White.copy(alpha = 0.85f), RoundedCornerShape(20.dp)),
        )
        Column(Modifier.fillMaxSize().safeDrawingPadding()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onClose) { Icon(Icons.Default.Close, contentDescription = "Close", tint = Color.White) }
                Text("Scan QR code", color = Color.White, style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.weight(1f))
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .background(Color.Black.copy(alpha = 0.65f), RoundedCornerShape(16.dp))
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    cameraError ?: status ?: "Point the camera at the QR code. Google Authenticator exports with several codes are imported one by one.",
                    color = Color.White,
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = onPickImage) { Text("Use a screenshot instead", color = Color.White) }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ManualEntryScreen(
    snackbar: SnackbarHostState,
    onAdd: (Account) -> Unit,
    onLink: (String) -> Unit,
    onBack: () -> Unit,
) {
    var issuer by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var secret by rememberSaveable { mutableStateOf("") }
    var advanced by rememberSaveable { mutableStateOf(false) }
    var hotp by rememberSaveable { mutableStateOf(false) }
    var algorithm by rememberSaveable { mutableStateOf(HashAlgorithm.SHA1) }
    var digits by rememberSaveable { mutableStateOf(6) }
    var period by rememberSaveable { mutableStateOf("30") }
    var counter by rememberSaveable { mutableStateOf("0") }
    var link by rememberSaveable { mutableStateOf("") }
    var error by rememberSaveable { mutableStateOf<String?>(null) }

    fun submit() {
        error = null
        if (issuer.isBlank() && name.isBlank()) {
            error = "Enter the service or account name."
            return
        }
        try {
            val account = Account(
                type = if (hotp) OtpType.HOTP else OtpType.TOTP,
                issuer = issuer.trim(),
                name = name.trim(),
                secret = Base32.decode(secret),
                algorithm = algorithm,
                digits = digits,
                period = if (hotp) 30 else period.trim().toIntOrNull() ?: throw OtpException("The period must be a number of seconds."),
                counter = if (hotp) counter.trim().toLongOrNull() ?: throw OtpException("The counter must be a number.") else 0,
            ).validate()
            onAdd(account)
        } catch (e: OtpException) {
            error = e.message
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Enter setup key") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
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
            OutlinedTextField(issuer, { issuer = it }, label = { Text("Service (e.g. GitHub)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(name, { name = it }, label = { Text("Account (e.g. you@example.com)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(
                secret,
                { secret = it },
                label = { Text("Secret key") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Advanced options", modifier = Modifier.weight(1f))
                Switch(checked = advanced, onCheckedChange = { advanced = it })
            }
            if (advanced) {
                Text("Type", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(selected = !hotp, onClick = { hotp = false }, label = { Text("Time-based (TOTP)") })
                    FilterChip(selected = hotp, onClick = { hotp = true }, label = { Text("Counter (HOTP)") })
                }
                Text("Algorithm", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    HashAlgorithm.entries.forEach { alg ->
                        FilterChip(selected = algorithm == alg, onClick = { algorithm = alg }, label = { Text(alg.jsonName) })
                    }
                }
                Text("Digits", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(6, 7, 8).forEach { d ->
                        FilterChip(selected = digits == d, onClick = { digits = d }, label = { Text("$d") })
                    }
                }
                if (hotp) {
                    OutlinedTextField(counter, { counter = it }, label = { Text("Counter") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
                } else {
                    OutlinedTextField(period, { period = it }, label = { Text("Period (seconds)") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
                }
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(onClick = ::submit, modifier = Modifier.fillMaxWidth()) { Text("Add account") }

            Spacer(Modifier.height(12.dp))
            Text("Or paste a link", style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                link,
                { link = it },
                label = { Text("otpauth://… or otpauth-migration://…") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
            FilledTonalButton(onClick = { if (link.isNotBlank()) onLink(link) }, modifier = Modifier.fillMaxWidth()) {
                Text("Add from link")
            }
        }
    }
}
