package now.elo.push

import android.Manifest
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.appcompat.app.AppCompatActivity
import android.content.pm.PackageManager
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.plugin.Invoke
import app.tauri.plugin.Channel
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailabilityLight
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

@InvokeArg
class RegisterArgs { var registration: String = ""; var background: Boolean = false }

@InvokeArg
class StatusArgs { var registration: String? = null }

@InvokeArg
class AckArgs { var opened: String? = null; var wake: String? = null }

@InvokeArg
class ReconcileArgs { var registration: String = ""; var unread: Boolean = false; var receipts: List<Map<String,String>> = emptyList(); var scopes: List<String> = emptyList(); var labels: Map<String,String> = emptyMap() }

@InvokeArg
class StatusListenerArgs { lateinit var channel: Channel }

@InvokeArg
class CallStateArgs { var active: Boolean = false; var sessionId: String = ""; var activation: String = ""; var camera: Boolean = false; var routeChannel: Channel? = null }

@InvokeArg
class CallAudioArgs { var sessionId: String = ""; var activation: String = ""; var outputId: String? = null }

@InvokeArg
class IncomingCallArgs { var payload: String = "" }

@TauriPlugin(permissions = [
    Permission(strings = [Manifest.permission.RECORD_AUDIO], alias = "microphone"),
    Permission(strings = [Manifest.permission.CAMERA], alias = "camera"),
])
class PushPlugin(private val activity: Activity) : Plugin(activity) {
    private val bindingsWorker = java.util.concurrent.Executors.newSingleThreadExecutor()
    @Command
    fun deviceModel(invoke: Invoke) {
        val result = JSObject()
        result.put("model", Build.MODEL)
        invoke.resolve(result)
    }

    private val prefs get() = activity.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var statusChannel: Channel? = null
    private val statusChanged = SharedPreferences.OnSharedPreferenceChangeListener { values, key ->
        if ((key in listOf("wake", "opened", "installation-id") || key?.startsWith("challenge:") == true) && values.getString(key, null) != null) {
            statusChannel?.send(JSObject())
        }
    }
    private fun available() = FirebaseApp.getApps(activity).isNotEmpty() &&
        GoogleApiAvailabilityLight.getInstance().isGooglePlayServicesAvailable(activity) == ConnectionResult.SUCCESS
    override fun load(webView: WebView) {
        super.load(webView)
        NativeMedia.attach(webView)
        prefs.registerOnSharedPreferenceChangeListener(statusChanged)
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(NotificationChannel("elo_messages", activity.getString(R.string.notification_channel_messages), NotificationManager.IMPORTANCE_DEFAULT).apply { setShowBadge(true) })
            manager.createNotificationChannel(NotificationChannel("elo_invitations", activity.getString(R.string.notification_channel_invitations), NotificationManager.IMPORTANCE_DEFAULT).apply { setShowBadge(true) })
        }
        ChatSessions.clearLegacy(activity)
        onIntent(activity.intent)
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); onIntent(intent) }
    override fun onWebViewDestroyed() {
        NativeMedia.attach(null)
        ChatSessions.detach(activity)
        statusChannel = null
        prefs.unregisterOnSharedPreferenceChangeListener(statusChanged)
        super.onWebViewDestroyed()
    }
    override fun onDestroy(activity: AppCompatActivity) {
        ChatSessions.detach(activity)
        prefs.unregisterOnSharedPreferenceChangeListener(statusChanged)
        statusChannel = null
        super.onDestroy(activity)
    }
    @Command
    fun statusListener(invoke: Invoke) {
        statusChannel = invoke.parseArgs(StatusListenerArgs::class.java).channel
        invoke.resolve()
    }
    @Command
    fun incomingListener(invoke: Invoke) {
        val channel = invoke.parseArgs(StatusListenerArgs::class.java).channel
        activity.runOnUiThread { IncomingCalls.listen(activity) { channel.send(it) }; invoke.resolve() }
    }
    @Command
    fun incomingStatus(invoke: Invoke) {
        activity.runOnUiThread { invoke.resolve(IncomingCalls.status(activity)) }
    }
    @Command
    fun incomingCall(invoke: Invoke) {
        val payload = invoke.parseArgs(IncomingCallArgs::class.java).payload
        activity.runOnUiThread {
            try {
                check(payload.length <= 8192) { "invalid_incoming_call_operation" }
                invoke.resolve(IncomingCalls.command(activity, JSONObject(payload)))
            } catch (_: Exception) { invoke.reject("incoming_call_unavailable") }
        }
    }
    @Command
    fun callBindings(invoke: Invoke) {
        val args = invoke.parseArgs(IncomingCallArgs::class.java)
        bindingsWorker.execute {
            try {
                require(args.payload.toByteArray(Charsets.UTF_8).size <= 2 * 1024 * 1024 + 1024)
                val request = JSONObject(args.payload)
                invoke.resolve(CallBindings.command(activity.applicationContext, request.getString("op"), request.optString("payload").takeIf { !request.isNull("payload") }))
            }
            catch (_: Exception) { invoke.reject("call_bindings_unavailable") }
        }
    }
    @Command
    fun nativeMedia(invoke: Invoke) {
        val args = invoke.parseArgs(IncomingCallArgs::class.java)
        activity.runOnUiThread {
            try {
                require(args.payload.toByteArray(Charsets.UTF_8).size <= 196608)
                val request = JSONObject(args.payload)
                if (request.optString("op") == "permissions") {
                    check(NativeMedia.foreground(activity)) { "NotAllowedError" }
                    val video = request.optBoolean("video")
                    if (NativeMedia.granted(activity, video)) invoke.resolve(JSObject())
                    else requestPermissionForAliases(if (video) arrayOf("microphone", "camera") else arrayOf("microphone"), invoke, "nativeMediaPermissionResult")
                } else NativeMedia.command(activity, request) { invoke.resolve(it) }
            } catch (_: Exception) { invoke.resolve(JSObject().put("error", "NotAllowedError")) }
        }
    }
    @PermissionCallback
    fun nativeMediaPermissionResult(invoke: Invoke) {
        val video = runCatching { JSONObject(invoke.parseArgs(IncomingCallArgs::class.java).payload).optBoolean("video") }.getOrDefault(false)
        invoke.resolve(if (NativeMedia.granted(activity, video)) JSObject() else JSObject().put("error", "NotAllowedError"))
    }
    private fun onIntent(intent: Intent?) {
        val target = intent?.getStringExtra("elo_target") ?: return
        if (prefs.getBoolean("enabled", false) && PushRegistrations.contains(prefs, intent.getStringExtra("elo_registration"))
            && target.length <= 2048 && target.matches(Regex("[A-Za-z0-9_-]{64,}"))) {
            prefs.edit().putString("wake", target).putString("opened", target)
                .putString("wake-registration", intent.getStringExtra("elo_registration"))
                .putString("opened-registration", intent.getStringExtra("elo_registration")).commit()
        }
        intent.removeExtra("elo_target")
    }
    @Command
    fun register(invoke: Invoke) {
        val args = invoke.parseArgs(RegisterArgs::class.java)
        if (!args.registration.matches(Regex("[a-f0-9]{32}"))) { invoke.reject("Invalid notification registration."); return }
        if (!available()) { invoke.reject("Notifications require Google Play services on this device."); return }
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            invoke.reject("Allow notifications in system settings."); return
        }
        if (!PushRegistrations.add(prefs, args.registration)) { invoke.reject("Too many notification registrations."); return }
        val token = prefs.getString("installation-id", null)
        if (prefs.getBoolean("enabled", false) && !token.isNullOrEmpty()) {
            invoke.resolve(JSObject().put("token", token)); return
        }
        prefs.edit().putBoolean("enabled", true).commit()
        val messaging = FirebaseMessaging.getInstance()
        messaging.isAutoInitEnabled = true
        val registration = PushRegistration.register()
        val finished = AtomicBoolean(false)
        val timeout = Runnable {
            if (finished.compareAndSet(false, true) && !args.background) {
                invoke.reject("Could not register notifications. Try again.")
            }
        }
        mainHandler.postDelayed(timeout, 15_000)
        registration.addOnCompleteListener { result ->
            if (!finished.compareAndSet(false, true)) return@addOnCompleteListener
            mainHandler.removeCallbacks(timeout)
            if (result.isSuccessful && prefs.getBoolean("enabled", false) &&
                PushRegistrations.contains(prefs, args.registration)) {
                prefs.edit().putString("installation-id", result.result).remove("token").apply()
                if (!args.background) invoke.resolve(JSObject().put("token", result.result))
            } else if (!args.background) { invoke.reject("Could not register notifications. Try again.") }
        }
        // Resume must not hold the profile lock while Firebase contacts the network.
        if (args.background) invoke.resolve()
    }
    @Command
    fun status(invoke: Invoke) {
        val requested = invoke.parseArgs(StatusArgs::class.java).registration
        val registration = requested?.takeIf { PushRegistrations.contains(prefs, it) }
        val value = JSObject().put("available", available())
            .put("enabled", prefs.getBoolean("enabled", false))
            .put("registration", registration)
            .put("token", prefs.getString("installation-id", null))
            .put("challenge", registration?.let { prefs.getString("challenge:$it", null) })
            .put("wake", if (requested == null || registration != null && PushRegistrations.targetRegistration(prefs, "wake") == registration) prefs.getString("wake", null) else null)
            .put("opened", if (requested == null || registration != null && PushRegistrations.targetRegistration(prefs, "opened") == registration) prefs.getString("opened", null) else null)
            .put("permission", NotificationManagerCompat.from(activity).areNotificationsEnabled())
        invoke.resolve(value)
    }
    @Command
    fun reconcile(invoke: Invoke) {
        NotificationInbox.reconcile(activity, invoke.parseArgs(ReconcileArgs::class.java))
        invoke.resolve()
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
    fun setCallState(invoke: Invoke) {
        val args = invoke.parseArgs(CallStateArgs::class.java)
        activity.runOnUiThread {
            try {
                ChatSessions.update(activity, args.sessionId, args.activation, args.active, args.camera) { error ->
                    if (error == null) {
                        ChatSessionAudio.listen(args.sessionId, args.activation, if (args.active) ({ value -> args.routeChannel?.send(value.put("sessionId", args.sessionId).put("activation", args.activation)); Unit }) else null)
                        invoke.resolve()
                    } else invoke.reject(error)
                }
            } catch (_: RuntimeException) {
                invoke.reject("Open the app and allow microphone or camera access to join a chat session.")
            }
        }
    }
    @Command
    fun callAudio(invoke: Invoke) {
        val args = invoke.parseArgs(CallAudioArgs::class.java)
        activity.runOnUiThread {
            try {
                if (IncomingCalls.ownsTelecom(args.sessionId) || OutgoingCalls.owns(args.sessionId)) {
                    check(ChatSessionAudio.owns(args.sessionId, args.activation))
                    val completed: (JSObject?, String?) -> Unit = { result, error ->
                        if (error != null) invoke.reject(error) else invoke.resolve(result)
                    }
                    if (IncomingCalls.ownsTelecom(args.sessionId)) IncomingCalls.route(args.sessionId, args.outputId, completed)
                    else OutgoingCalls.route(args.sessionId, args.outputId, completed)
                } else invoke.resolve(ChatSessionAudio.route(args.sessionId, args.activation, args.outputId))
            }
            catch (_: RuntimeException) { invoke.reject("unavailable") }
        }
    }
    @Command
    fun remove(invoke: Invoke) {
        val registration = invoke.parseArgs(RegisterArgs::class.java).registration
        activity.runOnUiThread { IncomingCalls.remove(activity, registration) }
        PushRegistrations.remove(prefs, registration)
        val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.activeNotifications.filter { it.notification.extras.getString("elo_registration") == registration }.forEach { manager.cancel(it.tag, it.id) }
        invoke.resolve()
    }
    @Command
    fun disable(invoke: Invoke) {
        activity.runOnUiThread { IncomingCalls.remove(activity) }
        prefs.edit().clear().commit()
        val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.activeNotifications.filter { it.tag?.startsWith("elo-wake:") == true }.forEach { manager.cancel(it.tag, it.id) }
        if (FirebaseApp.getApps(activity).isNotEmpty()) {
            FirebaseMessaging.getInstance().isAutoInitEnabled = false
            PushRegistration.unregister()
        }
        // Local delivery is already disabled. Let Rust revoke the server route
        // immediately; offline provider unregistration must not hold its lock.
        invoke.resolve()
    }
}
