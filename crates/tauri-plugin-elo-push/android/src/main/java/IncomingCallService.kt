package now.elo.push

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.Person
import androidx.core.app.ServiceCompat

/** Keeps only the Telecom call presentation alive; this service never captures media. */
class IncomingCallService : Service() {
    private val ownedKeys = mutableSetOf<String>()
    private var captureTypes = 0
    override fun onCreate() { super.onCreate(); instance = this }
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        IncomingCalls.initialize(this)
        val call = IncomingCalls.matching(intent?.getStringExtra(IncomingCalls.CALL_ID), intent?.getStringExtra(IncomingCalls.INVITATION_ID))
        if (intent?.action != IncomingCalls.SHOW || call == null || !IncomingCalls.isPresented(call.offer)) {
            if (IncomingCalls.calls().isEmpty()) stopSelf(startId)
            return START_NOT_STICKY
        }
        try {
            ownedKeys += call.offer.key
            // A waiting ring must not downgrade the microphone service of the
            // already admitted call, or a late SHOW replace the pending UI.
            ServiceCompat.startForeground(this, IncomingCalls.NOTIFICATION_ID, notification(this, IncomingCalls.active() ?: call),
                captureTypes or if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL else 0)
        } catch (_: RuntimeException) {
            IncomingCalls.reject(call.offer.callId, call.offer.invitationId, "unavailable")
            if (IncomingCalls.calls().isEmpty()) stopSelf(startId)
        }
        return START_NOT_STICKY
    }
    override fun onDestroy() {
        if (instance === this) {
            instance = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            IncomingCalls.calls().filter { it.offer.key in ownedKeys }.forEach { IncomingCalls.end(it.offer.callId, it.offer.invitationId) }
        }
        super.onDestroy()
    }
    companion object {
        private const val CHANNEL = "elo_calls_v1"
        private const val ONGOING_CHANNEL = "elo_calls_active_v1"
        private var silenced: String? = null
        private var instance: IncomingCallService? = null
        fun authorizeCapture(context: Context, mediaId: String, camera: Boolean) {
            check(IncomingCalls.authorizedMedia(mediaId)) { "NotAllowedError" }
            val service = checkNotNull(instance) { "unavailable" }
            val call = checkNotNull(IncomingCalls.active())
            // Only an explicit answer plus verified Rust admission may upgrade
            // this service to capture. A received push never requests the mic.
            val types = if (Build.VERSION.SDK_INT >= 30) ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL or
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE or (if (camera) ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA else 0)
                else if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL else 0
            ServiceCompat.startForeground(service, IncomingCalls.NOTIFICATION_ID, notification(context, call), types)
            service.captureTypes = types
        }
        fun refresh(context: Context) {
            val call = IncomingCalls.active() ?: return
            if (!IncomingCalls.isPresented(call.offer)) return
            runCatching { context.getSystemService(NotificationManager::class.java).notify(IncomingCalls.NOTIFICATION_ID, notification(context, call)) }
        }
        internal fun silence(context: Context, offer: IncomingCallState.Offer? = IncomingCalls.active()?.offer) {
            if (offer?.key != IncomingCalls.active()?.offer?.key) return
            silenced = offer?.key
            val call = IncomingCalls.active() ?: return
            val service = instance
            if (service != null) {
                val updated = runCatching {
                    ServiceCompat.startForeground(service, IncomingCalls.NOTIFICATION_ID, notification(context, call),
                        service.captureTypes or if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL else 0)
                }.isSuccess
                if (!updated) refresh(context)
            } else refresh(context)
        }
        private fun action(context: Context, offer: IncomingCallState.Offer, action: String, activity: Boolean): PendingIntent {
            val intent = Intent(context, if (activity) IncomingCallActivity::class.java else IncomingCallReceiver::class.java).apply {
                this.action = action
                data = Uri.parse("elo-call://${offer.callId}/${offer.invitationId}/$action")
                putExtra(IncomingCalls.CALL_ID, offer.callId)
                putExtra(IncomingCalls.INVITATION_ID, offer.invitationId)
                if (activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            return if (activity) PendingIntent.getActivity(context, 71007, intent, flags)
                else PendingIntent.getBroadcast(context, 71008, intent, flags)
        }
        private fun notification(context: Context, call: IncomingCallState.Call): Notification {
            val manager = context.getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.notification_channel_incoming_calls), NotificationManager.IMPORTANCE_HIGH).apply {
                setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE), AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
                enableVibration(true)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            })
            val ringing = call.phase == IncomingCallState.Phase.RINGING
            if (!ringing) manager.createNotificationChannel(NotificationChannel(ONGOING_CHANNEL,
                context.getString(R.string.notification_channel_active_calls), NotificationManager.IMPORTANCE_LOW).apply {
                setSound(null, null)
                enableVibration(false)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            })
            val person = Person.Builder().setName(context.getString(R.string.notification_incoming_call)).setImportant(true).build()
            val show = action(context, call.offer, IncomingCalls.SHOW, true)
            val decline = action(context, call.offer, IncomingCalls.DECLINE, false)
            val answer = action(context, call.offer, IncomingCalls.ANSWER, true)
            val end = action(context, call.offer, IncomingCalls.END, false)
            val builder = NotificationCompat.Builder(context, if (ringing) CHANNEL else ONGOING_CHANNEL)
                .setSmallIcon(R.drawable.ic_elo_notification).setContentTitle("elo.now")
                .setContentText(context.getString(if (ringing) R.string.notification_incoming_call else if (call.phase == IncomingCallState.Phase.ANSWERING) R.string.notification_connecting_call else R.string.notification_chat_session))
                .setContentIntent(show).setCategory(NotificationCompat.CATEGORY_CALL)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC).setOngoing(true).setOnlyAlertOnce(true)
                .setPriority(if (ringing) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_LOW)
                .setSilent(!ringing || silenced == call.offer.key)
                .setStyle(if (ringing) NotificationCompat.CallStyle.forIncomingCall(person, decline, answer)
                    else NotificationCompat.CallStyle.forOngoingCall(person, end))
            if (call.deadline != Long.MAX_VALUE) builder.setTimeoutAfter(maxOf(1, call.deadline - System.currentTimeMillis()))
            if (ringing && (Build.VERSION.SDK_INT < 34 || manager.canUseFullScreenIntent())) builder.setFullScreenIntent(show, true)
            return builder.build().apply {
                if (ringing && silenced != call.offer.key) flags = flags or Notification.FLAG_INSISTENT
            }
        }
    }
}

class IncomingCallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        IncomingCalls.initialize(context)
        val id = intent.getStringExtra(IncomingCalls.CALL_ID) ?: return
        val invitation = intent.getStringExtra(IncomingCalls.INVITATION_ID) ?: return
        when (intent.action) {
            IncomingCalls.DECLINE -> {
                IncomingCalls.reject(id, invitation)
                IncomingCalls.pendingDecline(id, invitation)?.let { ColdCallActions.decline(context, it, goAsync()) }
            }
            IncomingCalls.END -> IncomingCalls.end(id, invitation)
        }
    }
}
