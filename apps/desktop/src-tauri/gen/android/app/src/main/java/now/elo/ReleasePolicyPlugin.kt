package now.elo

import android.app.Activity
import android.content.Intent
import androidx.core.net.toUri
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

@TauriPlugin
class ReleasePolicyPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun openUpdate(invoke: Invoke) {
        activity.runOnUiThread {
            try {
                activity.startActivity(Intent(Intent.ACTION_VIEW, "https://play.google.com/store/apps/details?id=now.elo".toUri()))
                invoke.resolve()
            } catch (_: Exception) {
                invoke.reject("Could not open the download page.")
            }
        }
    }
}
