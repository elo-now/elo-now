package now.elo.push

import android.Manifest
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.Handler
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner

internal object ChatSessions {
    val state = ChatSessionState()
    const val NOTIFICATION_ID = 71002
    const val CHANNEL = "elo_chat_sessions"
    private val handler = Handler(Looper.getMainLooper())
    private val pending = mutableMapOf<Long, (String?) -> Unit>()

    fun update(activity: Activity, id: String, activation: String, active: Boolean, camera: Boolean, completed: (String?) -> Unit) {
        require(java.util.UUID.fromString(activation).toString() == activation)
        if (!active) {
            if (ChatSessionAudio.owns(id, activation)) stop(activity, id)
            completed(null)
            return
        }
        val foreground = !activity.isFinishing && !activity.isDestroyed &&
            (activity as? LifecycleOwner)?.lifecycle?.currentState?.isAtLeast(Lifecycle.State.RESUMED) == true
        val incomingMedia = IncomingCalls.authorizedCallMedia(id)
        check(IncomingCalls.active() == null || incomingMedia != null || OutgoingCalls.owns(id)) { "Incoming call authorization is required." }
        val session = state.begin(
            id, camera, foreground,
            ContextCompat.checkSelfPermission(activity, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED,
            ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
            authorizedIncoming = incomingMedia != null,
        )
        if (incomingMedia != null) {
            // The answered Telecom call already owns its foreground service and
            // audio routes. Do not start a second service from a locked Activity.
            try {
                IncomingCallService.authorizeCapture(activity, incomingMedia, camera)
                ChatSessionAudio.begin(activity, session.id, activation)
                completed(null)
            } catch (_: RuntimeException) {
                stop(activity, session.id)
                completed("Could not keep the chat session active.")
            }
            return
        }
        pending.values.toList().also { pending.clear() }.forEach { it("Chat session update was replaced.") }
        pending[session.revision] = completed
        handler.postDelayed({
            if (pending.containsKey(session.revision)) {
                complete(session, "Could not keep the chat session active.")
                stop(activity, session.id)
            }
        }, 4_000)
        try {
            ChatSessionAudio.begin(activity, session.id, activation)
            ContextCompat.startForegroundService(activity, Intent(activity, ChatSessionService::class.java)
                .setAction(ChatSessionState.ACTION)
                .putExtra(ChatSessionState.SESSION_ID, session.id)
                .putExtra(ChatSessionState.REVISION, session.revision))
        } catch (error: RuntimeException) {
            complete(session, "Could not keep the chat session active.")
            stop(activity, session.id)
        }
    }

    fun complete(session: ChatSessionState.Session, error: String?) {
        pending.remove(session.revision)?.invoke(error)
    }

    fun stop(context: Context, id: String? = null) {
        if (!state.end(id)) return
        ChatSessionAudio.stop(id)
        pending.values.toList().also { pending.clear() }.forEach { it("The chat session ended.") }
        context.stopService(Intent(context, ChatSessionService::class.java))
        context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
    }

    fun detach(context: Context) {
        val id = state.active()?.id
        if (id != null && (IncomingCalls.authorizedCallMedia(id) != null || OutgoingCalls.owns(id))) ChatSessionAudio.detach()
        else stop(context)
    }

    fun clearLegacy(context: Context) {
        val prefs = context.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
        val edit = prefs.edit()
        prefs.all.keys.filter { it.startsWith("call-") || it == "call" || it == "calls-enabled" }.forEach { edit.remove(it) }
        edit.apply()
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.notificationChannels.filter { it.id.startsWith("elo_calls_") && it.id != "elo_calls_v1" }.forEach { manager.deleteNotificationChannel(it.id) }
        if (state.active() == null) manager.cancel(NOTIFICATION_ID)
    }
}

/** Keeps user-started WebRTC capture alive; never starts capture or joins a chat itself. */
class ChatSessionService : Service() {
    private var owned: ChatSessionState.Session? = null
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val session = ChatSessions.state.matching(
            intent?.action,
            intent?.getStringExtra(ChatSessionState.SESSION_ID),
            intent?.getLongExtra(ChatSessionState.REVISION, -1) ?: -1,
        )
        if (session == null) {
            if (ChatSessions.state.active() == null) stopSelf(startId)
            return START_NOT_STICKY
        }
        val microphone = ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        val camera = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        if (!microphone || (session.camera && !camera)) {
            ChatSessions.complete(session, "Microphone or camera access is unavailable.")
            ChatSessions.stop(this, session.id)
            return START_NOT_STICKY
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            ChatSessions.CHANNEL, getString(R.string.notification_channel_chat_sessions), NotificationManager.IMPORTANCE_LOW,
        ).apply {
            setShowBadge(false)
            setSound(null, null)
            enableVibration(false)
        })
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        if (launch == null) {
            ChatSessions.complete(session, "Could not open the chat session.")
            ChatSessions.stop(this, session.id)
            return START_NOT_STICKY
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        launch.data = Uri.parse("elo-session://" + session.id)
        val open = PendingIntent.getActivity(this, 71006, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, ChatSessions.CHANNEL)
            .setSmallIcon(R.drawable.ic_elo_notification)
            .setContentTitle("elo.now")
            .setContentText(getString(R.string.notification_chat_session))
            .setContentIntent(open)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .build()
        val types = if (Build.VERSION.SDK_INT >= 30) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE or
                (if (session.camera) ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA else 0)
        } else 0
        try {
            ServiceCompat.startForeground(this, ChatSessions.NOTIFICATION_ID, notification, types)
            owned = session
            ChatSessions.complete(session, null)
        } catch (_: RuntimeException) {
            ChatSessions.complete(session, "Could not keep the chat session active.")
            ChatSessions.stop(this, session.id)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        owned?.let { if (ChatSessions.state.end(it.id, it.revision)) ChatSessionAudio.stop(it.id) }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
