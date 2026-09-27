package now.elo.push

import android.app.NotificationManager
import android.content.Context
import android.os.Bundle
import org.json.JSONObject

/** Only opaque event receipts and fixed catalog copy are retained outside the profile. */
internal object NotificationInbox {
    private const val READS = "notification-reads"
    private fun prefs(context: Context) = context.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    private fun reads(context: Context): JSONObject {
        val saved = try { JSONObject(prefs(context).getString(READS, "{}") ?: "{}") } catch (_: Exception) { JSONObject() }
        val now = System.currentTimeMillis()
        saved.keys().asSequence().toList().filter { saved.optLong(it) <= now }.forEach { saved.remove(it) }
        return saved
    }
    @Synchronized fun wasRead(context: Context, scope: String, event: String): Boolean = reads(context).has("$scope:$event")
    @Synchronized fun reconcile(context: Context, args: ReconcileArgs) {
        val prefs = prefs(context)
        if (!prefs.getBoolean("enabled", false) || prefs.getString("registration", null) != args.registration) return
        val saved = reads(context)
        args.receipts.take(1024).forEach { receipt ->
            val scope = receipt["scope"] ?: return@forEach
            val event = receipt["event"] ?: return@forEach
            if (scope.matches(Regex("[a-f0-9]{64}")) && event.matches(Regex("[a-f0-9]{64}"))) {
                saved.put("$scope:$event", System.currentTimeMillis() + 86_400_000)
            }
        }
        saved.keys().asSequence().toList().sortedBy { saved.optLong(it) }.take((saved.length() - 1024).coerceAtLeast(0)).forEach { saved.remove(it) }
        val edit = prefs.edit().putString(READS, saved.toString())
        for (key in listOf("notifications.nativeMessage", "notifications.nativeInvitation", "notifications.nativeActivity", "notifications.channelMessages", "notifications.channelInvitations")) {
            args.labels[key]?.takeIf { it.length <= 160 }?.let { edit.putString(key, it) }
        }
        edit.commit()
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.activeNotifications.filter { it.tag?.startsWith("elo-wake:") == true }.forEach { active ->
            val data = active.notification.extras
            val scope = data.getString("elo_scope") ?: return@forEach
            val event = data.getString("elo_event") ?: ""
            if (data.getString("elo_registration") != args.registration || scope !in args.scopes || saved.has("$scope:$event")) {
                manager.cancel(active.tag, active.id)
            }
        }
    }
    @Synchronized fun post(context: Context, registration: String?, scope: String, event: String, notification: android.app.Notification) {
        val current = prefs(context)
        if (!current.getBoolean("enabled", false) || current.getString("registration", null) != registration || wasRead(context, scope, event)) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify("elo-wake:$scope", 71001, notification)
    }
    fun metadata(registration: String?, scope: String, event: String) = Bundle().apply {
        putString("elo_registration", registration); putString("elo_scope", scope); putString("elo_event", event)
    }
}
