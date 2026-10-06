package now.elo.push

import android.content.BroadcastReceiver
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Base64
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** A notification decline can use its call-only delegation without creating a WebView. */
internal object ColdCallActions {
    private val worker = Executors.newSingleThreadExecutor { runnable -> Thread(runnable, "elo-call-decline") }
    private val main = Handler(Looper.getMainLooper())
    @JvmStatic private external fun nativeDecline(context: Context, enrollment: ByteArray, event: String): Boolean

    fun decline(context: Context, event: JSONObject, pending: BroadcastReceiver.PendingResult) {
        val application = context.applicationContext
        val deadline = SystemClock.elapsedRealtime() + 8_000
        val completed = AtomicBoolean(false)
        val timeout = Runnable { if (completed.compareAndSet(false, true)) pending.finish() }
        main.postDelayed(timeout, 8_000)
        worker.execute {
            var enrollment: ByteArray? = null
            var acknowledged = false
            try {
                if (SystemClock.elapsedRealtime() >= deadline) return@execute
                val saved = CallBindings.command(application, "load", null)
                if (saved.isNull("payload")) return@execute
                enrollment = Base64.decode(saved.getString("payload"), Base64.DEFAULT)
                System.loadLibrary("elo_app_lib")
                // Rust bounds network work below this receiver's eight-second
                // lifetime and authenticates the original call invitation.
                if (SystemClock.elapsedRealtime() < deadline) acknowledged = nativeDecline(application, enrollment, event.toString())
            } catch (_: Exception) {
                // Pending remains durable for the next application bootstrap.
            } catch (_: LinkageError) {
                // An incompatible native library must not lose the user's action.
            } finally {
                enrollment?.fill(0)
                val success = acknowledged && SystemClock.elapsedRealtime() < deadline
                main.post {
                    if (completed.compareAndSet(false, true)) {
                        main.removeCallbacks(timeout)
                        if (success) runCatching { IncomingCalls.command(application, JSONObject().put("op", "ack").put("eventId", event.getString("eventId"))) }
                        pending.finish()
                    }
                }
            }
        }
    }
}
