package now.elo.push

import android.Manifest
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.webkit.WebView
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import android.content.pm.PackageManager
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging

@InvokeArg
class RegisterArgs { var registration: String = "" }

@InvokeArg
class AckArgs { var opened: String? = null; var wake: String? = null }

@TauriPlugin
class PushPlugin(private val activity: Activity) : Plugin(activity) {
    private val prefs get() = activity.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    override fun load(webView: WebView) {
        super.load(webView)
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(NotificationChannel("elo_messages", "Messages", NotificationManager.IMPORTANCE_DEFAULT))
        }
        onIntent(activity.intent)
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); onIntent(intent) }
    private fun onIntent(intent: Intent?) {
        val target = intent?.getStringExtra("elo_target") ?: return
        if (prefs.getBoolean("enabled", false) && intent.getStringExtra("elo_registration") == prefs.getString("registration", null)
            && target.length <= 2048 && target.matches(Regex("[A-Za-z0-9_-]{64,}"))) {
            prefs.edit().putString("wake", target).putString("opened", target).commit()
        }
        intent.removeExtra("elo_target")
    }
    @Command
    fun register(invoke: Invoke) {
        val args = invoke.parseArgs(RegisterArgs::class.java)
        if (!args.registration.matches(Regex("[a-f0-9]{32}"))) { invoke.reject("Invalid notification registration."); return }
        if (FirebaseApp.getApps(activity).isEmpty()) { invoke.reject("Notifications are not configured."); return }
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            invoke.reject("Allow notifications in system settings."); return
        }
        prefs.edit().putString("registration", args.registration).remove("challenge").putBoolean("enabled", true).commit()
        FirebaseMessaging.getInstance().isAutoInitEnabled = true
        FirebaseMessaging.getInstance().token.addOnCompleteListener { result ->
            if (result.isSuccessful) {
                prefs.edit().putString("token", result.result).apply()
                invoke.resolve(JSObject().put("token", result.result))
            } else { invoke.reject("Could not register notifications. Try again.") }
        }
    }
    @Command
    fun status(invoke: Invoke) {
        val value = JSObject().put("available", FirebaseApp.getApps(activity).isNotEmpty())
            .put("enabled", prefs.getBoolean("enabled", false))
            .put("token", prefs.getString("token", null))
            .put("challenge", prefs.getString("challenge", null))
            .put("wake", prefs.getString("wake", null))
            .put("opened", prefs.getString("opened", null))
            .put("permission", NotificationManagerCompat.from(activity).areNotificationsEnabled())
        invoke.resolve(value)
    }
    @Command
    fun ack(invoke: Invoke) {
        val args = invoke.parseArgs(AckArgs::class.java)
        val edit = prefs.edit()
        for ((key, value) in listOf("opened" to args.opened, "wake" to args.wake)) {
            if (value != null && prefs.getString(key, null) == value) edit.remove(key)
        }
        edit.commit()
        invoke.resolve()
    }
    @Command
    fun disable(invoke: Invoke) {
        prefs.edit().clear().commit()
        val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.activeNotifications.filter { it.tag?.startsWith("elo-wake:") == true }.forEach { manager.cancel(it.tag, it.id) }
        if (FirebaseApp.getApps(activity).isNotEmpty()) {
            FirebaseMessaging.getInstance().isAutoInitEnabled = false
            FirebaseMessaging.getInstance().deleteToken().addOnCompleteListener { invoke.resolve() }
        } else { invoke.resolve() }
    }
}
