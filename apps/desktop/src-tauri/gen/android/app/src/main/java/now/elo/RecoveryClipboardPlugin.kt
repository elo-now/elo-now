package now.elo

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin
import java.util.UUID
import androidx.core.content.edit

@InvokeArg
class RecoveryClipboardArgs { var text: String = "" }

@TauriPlugin
class RecoveryClipboardPlugin(private val activity: Activity) : Plugin(activity) {
    private val handler = Handler(Looper.getMainLooper())
    private val preferences = activity.getSharedPreferences("elo.clipboard.expiry", Context.MODE_PRIVATE)
    private val clipboard get() = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val expire = Runnable { clearExpired() }

    init { handler.post { clearExpired() } }

    @Command
    fun copyRecoveryCode(invoke: Invoke) {
        val args = invoke.parseArgs(RecoveryClipboardArgs::class.java)
        if (args.text.isEmpty() || args.text.toByteArray(Charsets.UTF_8).size > 2048 || args.text.contains('\u0000')) {
            invoke.reject("Could not copy the recovery code.")
            return
        }
        activity.runOnUiThread {
            try {
            val label = "elo.recovery.${UUID.randomUUID()}"
            val clip = ClipData.newPlainText(label, args.text)
            clip.description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
            clipboard.setPrimaryClip(clip)
            // Persist only an opaque ownership marker and expiry, never the code.
            preferences.edit {
                putString("label", label)
                putLong("expires", System.currentTimeMillis() + 60_000)
            }
            handler.removeCallbacks(expire)
            handler.postDelayed(expire, 60_000)
            invoke.resolve()
            } catch (_: Exception) {
                invoke.reject("Could not copy the recovery code.")
            }
        }
    }

    override fun onResume() {
        super.onResume()
        clearExpired()
    }

    private fun clearExpired() {
        val label = preferences.getString("label", null) ?: return
        if (System.currentTimeMillis() < preferences.getLong("expires", 0)) return
        // Android may deny clipboard access in the background. In that case
        // retain the marker and retry when the activity becomes visible.
        try {
        val description = clipboard.primaryClipDescription ?: return
        if (description.label?.toString() == label) {
            if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
            else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
        preferences.edit { clear() }
        } catch (_: Exception) {
            // Retry after returning to the foreground if the OS denies access.
        }
    }
}
