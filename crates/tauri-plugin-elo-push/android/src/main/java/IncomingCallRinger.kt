package now.elo.push

import android.app.NotificationManager
import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.net.Uri
import android.os.Build
import android.os.PowerManager

/** Owns a bounded call's sound; notification repetition differs between vendors. */
internal class IncomingCallRinger(private val context: Context) {
    private val audio = context.getSystemService(AudioManager::class.java)
    private val notifications = context.getSystemService(NotificationManager::class.java)
    private val attributes = AudioAttributes.Builder()
        .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build()
    private var player: MediaPlayer? = null
    private var current: String? = null
    private var interrupted = false

    fun update(callId: String?, tone: String, channel: String) {
        val key = callId?.let { "$it:$tone" }
        if (current != key) {
            stopSound()
            current = key
            interrupted = false
        }
        val channelEnabled = Build.VERSION.SDK_INT < 26 ||
            (notifications.getNotificationChannel(channel)?.importance ?: 0) >= NotificationManager.IMPORTANCE_DEFAULT
        if (key == null || tone == "silent" || interrupted || !channelEnabled ||
            !notifications.areNotificationsEnabled() ||
            notifications.currentInterruptionFilter != NotificationManager.INTERRUPTION_FILTER_ALL ||
            audio.ringerMode != AudioManager.RINGER_MODE_NORMAL || audio.getStreamVolume(AudioManager.STREAM_RING) == 0) {
            stopSound()
            return
        }
        if (player != null) return
        val resource = context.resources.getIdentifier("elo_ring_$tone", "raw", context.packageName)
        if (resource == 0) return
        // Telecom owns focus for this self-managed Connection. A second request
        // competes with Telecom itself and cuts off the ringtone on Android 10.
        // ConnectionService focus loss and Connection.onSilence stop this loop.
        val next = MediaPlayer()
        try {
            next.setAudioAttributes(attributes)
            next.setWakeMode(context, PowerManager.PARTIAL_WAKE_LOCK)
            next.setDataSource(context, Uri.parse("android.resource://${context.packageName}/$resource"))
            next.isLooping = true
            next.setOnErrorListener { _, _, _ ->
                interrupted = true
                stopSound()
                true
            }
            next.prepare()
            player = next
            next.start()
        } catch (_: Exception) {
            if (player !== next) next.release()
            interrupted = true
            stopSound()
        }
    }

    fun stop() {
        current = null
        interrupted = false
        stopSound()
    }

    private fun stopSound() {
        player?.release()
        player = null
    }
}
