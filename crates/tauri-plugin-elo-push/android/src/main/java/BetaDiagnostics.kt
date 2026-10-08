package now.elo.push

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.crashlytics.FirebaseCrashlytics
import org.json.JSONObject

internal object BetaDiagnostics {
    @Volatile private var enabled = false

    @Synchronized fun command(context: Context, body: JSONObject) {
        if (FirebaseApp.getApps(context).isEmpty()) return
        val sdk = FirebaseCrashlytics.getInstance()
        if (body.optString("op") == "configure") {
            sdk.setCrashlyticsCollectionEnabled(false)
            enabled = body.optBoolean("enabled", false)
            if (enabled) {
                sdk.setCustomKey("distribution", "beta")
                sdk.setUserId(body.optString("installation", ""))
                sdk.sendUnsentReports()
            } else {
                sdk.setUserId("")
                sdk.deleteUnsentReports()
            }
            return
        }
        if (!enabled) return
        val code = body.optString("code")
        if (code.length > 100 || !code.matches(Regex("[A-Za-z0-9_.:-]+"))) return
        val source = body.optString("source", "unknown")
        sdk.log("$source:$code duration_ms=${body.optLong("elapsed_ms", 0)}")
        if (body.optString("kind") == "error") {
            // Never attach the original exception/cause: it can contain tokens,
            // network URLs, filenames or user-authored content.
            sdk.recordException(IllegalStateException("elo.$source.$code"))
        }
    }

    fun mediaFailure(error: Exception, stage: String) {
        if (!enabled) return
        val sdk = FirebaseCrashlytics.getInstance()
        val category = when (error) {
            is SecurityException -> "permission"
            is java.net.SocketTimeoutException -> "timeout"
            is java.io.IOException -> "io"
            else -> "native"
        }
        sdk.log("media:$stage category=$category")
        sdk.recordException(IllegalStateException("elo.media.$stage.$category"))
    }
}
