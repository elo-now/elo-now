package now.elo.push

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class PushService : FirebaseMessagingService() {
    private val prefs get() = getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    override fun onRegistered(installationId: String) {
        if (prefs.getBoolean("enabled", false)) {
            prefs.edit().putString("installation-id", installationId).apply()
        }
    }
    override fun onMessageReceived(message: RemoteMessage) {
        if (!prefs.getBoolean("enabled", false) || message.data["elo_registration"] != prefs.getString("registration", null)) return
        if(message.data["elo_call"]=="1") { IncomingCalls.receive(this,message.data);return }
        val challenge = message.data["elo_challenge"]
        if (challenge != null && challenge.matches(Regex("[a-f0-9]{64}")) &&
            message.data["elo_registration"] == prefs.getString("registration", null)) {
            prefs.edit().putString("challenge", challenge).apply()
            return
        }
        if (message.data["elo_wake"] != "1") return
        val target = message.data["elo_target"] ?: return
        val scope = message.data["elo_scope"] ?: return
        val event = message.data["elo_event"] ?: return
        if (!event.matches(Regex("[a-f0-9]{64}")) || NotificationInbox.wasRead(this, scope, event)) return
        if (target.length > 2048 || !target.matches(Regex("[A-Za-z0-9_-]{64,}")) || !scope.matches(Regex("[a-f0-9]{64}"))) return
        prefs.edit().putString("wake", target).commit()
        val foreground = ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return
        launch.data = Uri.parse("elo-notification://" + scope)
        launch.putExtra("elo_target", target).putExtra("elo_registration", message.data["elo_registration"]).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pending = PendingIntent.getActivity(this, 71001, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        // Use fixed local copy only. Incoming payload text is never rendered.
        // Keep a silent drawer entry for launcher badges. The verified foreground UI owns alerts.
        val quiet = foreground || message.data["elo_quiet"] == "1"
        val category = message.data["elo_category"] ?: "message"
        val (key, fallback) = when (category) {
            "invitation" -> "notifications.nativeInvitation" to R.string.notification_invitation
            "membership" -> "notifications.nativeActivity" to R.string.notification_activity
            else -> "notifications.nativeMessage" to R.string.notification_message
        }
        val channel = if (category == "message") "elo_messages" else "elo_invitations"
        val notification = NotificationCompat.Builder(this, channel)
            .setSmallIcon(now.elo.push.R.drawable.ic_elo_notification).setContentTitle("elo.now")
            .setContentText(prefs.getString(key, getString(fallback)))
            .addExtras(NotificationInbox.metadata(message.data["elo_registration"], scope, event))
            .setNumber(1)
            .setContentIntent(pending).setAutoCancel(true).setOnlyAlertOnce(quiet).setSilent(quiet)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE).build()
        NotificationInbox.post(this, message.data["elo_registration"], scope, event, notification)
    }
}
