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
import app.tauri.plugin.Invoke
import app.tauri.plugin.Channel
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailabilityLight
import com.google.android.gms.tasks.Task
import java.util.concurrent.atomic.AtomicBoolean

@InvokeArg
class RegisterArgs { var registration: String = "" }

@InvokeArg
class AckArgs { var opened: String? = null; var wake: String? = null }

@InvokeArg
class StatusListenerArgs { lateinit var channel: Channel }

@InvokeArg
class CallConfigureArgs { var enabled:Boolean=false;var registration:String="";var endpoint:String="";var labels:Map<String,String> = emptyMap();var ringtone:String?=null }
@InvokeArg
class CallActionArgs { var action:String="";var callId:String="";var event:String?=null }

@TauriPlugin
class PushPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun deviceModel(invoke: Invoke) {
        val result = JSObject()
        result.put("model", Build.MODEL)
        invoke.resolve(result)
    }

    private val prefs get() = activity.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    private var tokenDeletion: Task<Void>? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var statusChannel: Channel? = null
    private val statusChanged = SharedPreferences.OnSharedPreferenceChangeListener { values, key ->
        if (key in listOf("wake", "opened", "challenge") && values.getString(key, null) != null) {
            statusChannel?.send(JSObject())
        }
    }
    private fun available() = FirebaseApp.getApps(activity).isNotEmpty() &&
        GoogleApiAvailabilityLight.getInstance().isGooglePlayServicesAvailable(activity) == ConnectionResult.SUCCESS
    override fun load(webView: WebView) {
        super.load(webView)
        prefs.registerOnSharedPreferenceChangeListener(statusChanged)
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(NotificationChannel("elo_messages", "Messages", NotificationManager.IMPORTANCE_DEFAULT))
        }
        onIntent(activity.intent)
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); onIntent(intent) }
    override fun onDestroy(activity: AppCompatActivity) {
        prefs.unregisterOnSharedPreferenceChangeListener(statusChanged)
        statusChannel = null
        super.onDestroy(activity)
    }
    @Command
    fun statusListener(invoke: Invoke) {
        statusChannel = invoke.parseArgs(StatusListenerArgs::class.java).channel
        invoke.resolve()
    }
    private fun onIntent(intent: Intent?) {
        val target = intent?.getStringExtra("elo_target") ?: return
        if (prefs.getBoolean("enabled", false) && intent.getStringExtra("elo_registration") == prefs.getString("registration", null)
            && target.length <= 2048 && target.matches(Regex("[A-Za-z0-9_-]{64,}"))) {
            prefs.edit().putString("wake", target).putString("opened", target).commit()
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
        prefs.edit().putString("registration", args.registration).remove("challenge").putBoolean("enabled", true).commit()
        val messaging = FirebaseMessaging.getInstance()
        messaging.isAutoInitEnabled = true
        // A quick re-enable must obtain its token after an earlier deletion.
        val token = tokenDeletion?.continueWithTask { messaging.token } ?: messaging.token
        val finished = AtomicBoolean(false)
        val timeout = Runnable {
            if (finished.compareAndSet(false, true)) {
                invoke.reject("Could not register notifications. Try again.")
            }
        }
        mainHandler.postDelayed(timeout, 15_000)
        token.addOnCompleteListener { result ->
            if (!finished.compareAndSet(false, true)) return@addOnCompleteListener
            mainHandler.removeCallbacks(timeout)
            if (result.isSuccessful) {
                prefs.edit().putString("token", result.result).apply()
                invoke.resolve(JSObject().put("token", result.result))
            } else { invoke.reject("Could not register notifications. Try again.") }
        }
    }
    @Command
    fun status(invoke: Invoke) {
        val value = JSObject().put("available", available())
            .put("enabled", prefs.getBoolean("enabled", false))
            .put("token", prefs.getString("token", null))
            .put("challenge", prefs.getString("challenge", null))
            .put("wake", prefs.getString("wake", null))
            .put("opened", prefs.getString("opened", null))
            .put("permission", NotificationManagerCompat.from(activity).areNotificationsEnabled())
        invoke.resolve(value)
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
    fun callConfigure(invoke:Invoke) {
        val args=invoke.parseArgs(CallConfigureArgs::class.java)
        if(args.registration!=prefs.getString("registration",null) || !args.endpoint.startsWith("https://")) { invoke.reject("Invalid call registration");return }
        val edit=prefs.edit().putBoolean("calls-enabled",args.enabled).putString("call-endpoint",args.endpoint)
        for((key,value) in args.labels) if(key in listOf("incoming","answer","decline","unlock","connected") && value.length<=160) edit.putString("call-label-$key",value)
        if(args.ringtone in listOf("classic","chime","pulse","silent")) edit.putString("call-ringtone",args.ringtone)
        edit.commit()
        IncomingCalls.current(activity)?.let {
            if(!args.enabled || (it.optBoolean("connected") && EloConnectionService.connection==null)) IncomingCalls.finish(activity,it.optString("id"))
        }
        invoke.resolve(JSObject().put("token",prefs.getString("token",null)))
    }
    @Command
    fun callStatus(invoke:Invoke) {
        val call=(try { org.json.JSONObject(prefs.getString("call-event","") ?: "") } catch (_:Exception) { null }) ?: IncomingCalls.current(activity)
        invoke.resolve(JSObject().put("incoming",call?.let { JSObject(it.toString()) }))
    }
    @Command
    fun callAction(invoke:Invoke) {
        val args=invoke.parseArgs(CallActionArgs::class.java)
        if(args.action=="ack") {
            val event=try { org.json.JSONObject(prefs.getString("call-event","") ?: "") } catch (_:Exception) { null }
            if(event?.optString("id")==args.callId && event.optString("event")==args.event) prefs.edit().remove("call-event").commit()
        }
        when(args.action) { "answering"->IncomingCalls.answer(activity,args.callId);"connected"->IncomingCalls.connected(activity,args.callId);"end"->IncomingCalls.finish(activity,args.callId) }
        invoke.resolve()
    }
    @Command
    fun disable(invoke: Invoke) {
        IncomingCalls.current(activity)?.optString("id")?.let { IncomingCalls.finish(activity,it) }
        prefs.edit().clear().commit()
        val manager = activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.activeNotifications.filter { it.tag?.startsWith("elo-wake:") == true }.forEach { manager.cancel(it.tag, it.id) }
        if (FirebaseApp.getApps(activity).isNotEmpty()) {
            FirebaseMessaging.getInstance().isAutoInitEnabled = false
            if (tokenDeletion?.isComplete != false) {
                tokenDeletion = FirebaseMessaging.getInstance().deleteToken()
            }
        }
        // Local delivery is already disabled. Let Rust revoke the server route
        // immediately; an offline Firebase token deletion must not hold its lock.
        invoke.resolve()
    }
}
