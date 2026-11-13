package app.authenticator

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/** Copies codes marked as sensitive and removes them again after a while. */
object Clipboard {
    private const val LABEL = "Authenticator code"
    const val CLEAR_AFTER_MS = 30_000L

    private val handler = Handler(Looper.getMainLooper())
    private var copiedAt = 0L

    fun copy(context: Context, code: String, clearLater: Boolean) {
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(LABEL, code)
        clip.description.extras = PersistableBundle().apply {
            // Hides the code in the clipboard preview and keyboard suggestions.
            if (Build.VERSION.SDK_INT >= 33) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        manager.setPrimaryClip(clip)
        copiedAt = System.currentTimeMillis()
        handler.removeCallbacksAndMessages(null)
        if (clearLater) {
            val app = context.applicationContext
            handler.postDelayed({ clearIfOurs(app) }, CLEAR_AFTER_MS)
        }
    }

    /** Also called when the app returns to the foreground (reading the clipboard needs focus). */
    fun clearIfExpired(context: Context) {
        if (copiedAt != 0L && System.currentTimeMillis() - copiedAt >= CLEAR_AFTER_MS) clearIfOurs(context)
    }

    private fun clearIfOurs(context: Context) {
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return
        // Only clear if the clipboard still holds our code (never wipe something else the user copied).
        val ours = runCatching { manager.primaryClipDescription?.label == LABEL }.getOrDefault(false)
        if (!ours) return
        copiedAt = 0L
        if (Build.VERSION.SDK_INT >= 28) {
            manager.clearPrimaryClip()
        } else {
            manager.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }

    /** Android 13+ shows its own confirmation when something is copied. */
    val systemShowsConfirmation: Boolean get() = Build.VERSION.SDK_INT >= 33
}
