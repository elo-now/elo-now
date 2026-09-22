package now.elo.push

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class PushService : FirebaseMessagingService() {
    private val prefs get() = getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    override fun onNewToken(token: String) { prefs.edit().putString("token", token).apply() }
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
        if (target.length > 2048 || !target.matches(Regex("[A-Za-z0-9_-]{64,}")) || !scope.matches(Regex("[a-f0-9]{64}"))) return
        prefs.edit().putString("wake", target).commit()
        if (ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return
        launch.data = Uri.parse("elo-notification://" + scope)
        launch.putExtra("elo_target", target).putExtra("elo_registration", message.data["elo_registration"]).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pending = PendingIntent.getActivity(this, 71001, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        // Use fixed local copy only. Incoming payload text is never rendered.
        val quiet = message.data["elo_quiet"] == "1"
        val notification = NotificationCompat.Builder(this, "elo_messages")
            .setSmallIcon(now.elo.push.R.drawable.ic_elo_notification).setContentTitle("elo.now")
            .setContentText("New messages")
            .setContentIntent(pending).setAutoCancel(true).setOnlyAlertOnce(quiet).setSilent(quiet)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE).build()
        NotificationManagerCompat.from(this).notify("elo-wake:" + scope, 71001, notification)
    }
}
