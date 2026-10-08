package now.elo.push

import android.app.Activity
import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.Ringtone
import android.media.RingtoneManager
import android.media.ToneGenerator
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.lang.ref.WeakReference

/** Foreground alert only; never requests capture permission or audio focus. */
internal object ForegroundRingtone {
    private val state = ForegroundRingtoneState()
    private val main = Handler(Looper.getMainLooper())
    private var activity = WeakReference<Activity>(null)
    private var ringtone: Ringtone? = null
    private var waitingTone: ToneGenerator? = null
    private var waiting = false
    private var nextTone = 0L
    private val lifecycle = object : DefaultLifecycleObserver {
        override fun onPause(owner: LifecycleOwner) { stop() }
        override fun onStop(owner: LifecycleOwner) { stop() }
        override fun onDestroy(owner: LifecycleOwner) { stop(); activity.clear() }
    }
    private val tick = object : Runnable {
        override fun run() {
            val owner = activity.get()
            if (owner == null || !state.live(System.currentTimeMillis()) || !foreground(owner)) { stop(); return }
            if (IncomingCalls.hasAnsweredPresentation()) { stop(); return }
            if (!audible(owner) || IncomingCalls.hasRingingPresentation()) {
                pausePlayback()
                main.postDelayed(this, 200)
                return
            }
            val now = System.currentTimeMillis()
            val currentWaiting = ChatSessions.state.active() != null
            if (waiting != currentWaiting) { releasePlayer(); waiting = currentWaiting; nextTone = 0 }
            if (now >= nextTone) {
                runCatching {
                    if (waiting) {
                        if (waitingTone == null) waitingTone = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 18)
                        waitingTone?.startTone(ToneGenerator.TONE_SUP_CALL_WAITING, 400)
                        nextTone = now + 8_000
                    } else {
                        if (ringtone == null) {
                            val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
                            ringtone = RingtoneManager.getRingtone(owner.applicationContext, uri)?.apply {
                                audioAttributes = AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build()
                                if (Build.VERSION.SDK_INT >= 28) isLooping = true
                            }
                        }
                        if (ringtone?.isPlaying != true) ringtone?.play()
                        nextTone = now + 1_000
                    }
                }.onFailure { stop(); return }
            }
            main.postDelayed(this, 200)
        }
    }

    fun attach(owner: Activity) {
        (activity.get() as? LifecycleOwner)?.lifecycle?.removeObserver(lifecycle)
        stop()
        activity = WeakReference(owner)
        (owner as? LifecycleOwner)?.lifecycle?.addObserver(lifecycle)
    }

    fun update(owner: Activity, epoch: Long, token: String, revision: Long, enabled: Boolean, expires: Long) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!state.admit(epoch)) return
        val previous = state.token
        state.update(token, revision, enabled, expires, System.currentTimeMillis())
        if (state.token != previous) { releasePlayer(); nextTone = 0 }
        main.removeCallbacks(tick)
        if (IncomingCalls.hasAnsweredPresentation()) { stop(); return }
        if (!state.live(System.currentTimeMillis()) || !foreground(owner)) { stop(); return }
        tick.run()
    }

    private fun foreground(owner: Activity) = NativeMedia.foreground(owner) &&
        !owner.getSystemService(KeyguardManager::class.java).isKeyguardLocked

    private fun audible(owner: Activity): Boolean {
        val audio = owner.getSystemService(AudioManager::class.java)
        val notifications = owner.getSystemService(NotificationManager::class.java)
        return audio.ringerMode == AudioManager.RINGER_MODE_NORMAL &&
            notifications.currentInterruptionFilter == NotificationManager.INTERRUPTION_FILTER_ALL
    }

    fun stop() {
        state.stop()
        main.removeCallbacks(tick)
        releasePlayer()
    }

    fun shutdown(epoch: Long) { if (state.admit(epoch)) stop() }

    fun pausePlayback() { releasePlayer(); nextTone = 0 }

    private fun releasePlayer() {
        runCatching { ringtone?.stop() }
        ringtone = null
        runCatching { waitingTone?.stopTone(); waitingTone?.release() }
        waitingTone = null
    }
}
