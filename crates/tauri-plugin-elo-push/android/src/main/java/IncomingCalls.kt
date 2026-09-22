package now.elo.push

import android.app.*
import android.content.*
import android.net.Uri
import android.os.*
import android.telecom.*
import androidx.core.app.NotificationCompat
import androidx.core.app.Person
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Contains only an encrypted destination and a short-lived ring-status capability. */
object IncomingCalls {
    fun prefs(c: Context) = c.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
    fun current(c: Context): JSONObject? = try { JSONObject(prefs(c).getString("call", "") ?: "") } catch (_: Exception) { null }
    fun label(c: Context, key: String) = prefs(c).getString("call-label-$key", "elo.now") ?: "elo.now"
    fun account(c: Context) = PhoneAccountHandle(ComponentName(c, EloConnectionService::class.java), "elo-calls")
    fun save(c: Context, call: JSONObject) { prefs(c).edit().putString("call",call.toString()).commit() }
    fun receive(c: Context, data: Map<String,String>) {
        val p=prefs(c)
        if (!p.getBoolean("calls-enabled",false) || !p.getBoolean("enabled",false) || data["elo_registration"] != p.getString("registration",null)) return
        val id=data["elo_call_id"] ?: return
        val expires=data["elo_expires"]?.toLongOrNull() ?: return
        val now=System.currentTimeMillis()/1000
        val target=data["elo_target"] ?: return
        val ticket=data["elo_ticket"] ?: return
        if (!id.matches(Regex("[a-f0-9]{32}")) || expires<=now || expires>now+60 || target.length>2048 || !target.matches(Regex("[A-Za-z0-9_-]{64,}")) || !ticket.matches(Regex("[a-f0-9]{64}"))) return
        current(c)?.takeIf { !it.optBoolean("connected") && it.optLong("expires")<=now }?.let { finish(c,it.optString("id")) }
        if (current(c)?.optString("id")==id || p.getString("call-last",null)==id) return
        if (current(c)!=null) return
        val call=JSONObject().put("id",id).put("target",target).put("expires",expires).put("ticket",ticket)
            .put("registration",data["elo_registration"]).put("action","ring").put("connected",false)
        save(c,call)
        try {
            val telecom=c.getSystemService(TelecomManager::class.java)
            telecom.registerPhoneAccount(PhoneAccount.builder(account(c),"elo.now").setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED).build())
            telecom.addNewIncomingCall(account(c),Bundle())
        } catch (_: Exception) { finish(c,id) }
    }
    fun finish(c: Context,id: String) {
        if (current(c)?.optString("id")!=id) return
        prefs(c).edit().remove("call").putString("call-last",id).commit()
        c.getSystemService(NotificationManager::class.java).cancel(71002)
        c.stopService(Intent(c,IncomingCallService::class.java))
        EloConnectionService.connection?.let { it.setDisconnected(DisconnectCause(DisconnectCause.LOCAL)); it.destroy() }
        EloConnectionService.connection=null
    }
    fun event(c:Context, call:JSONObject, action:String, muted:Boolean?=null) {
        val value=JSONObject(call.toString()).put("action",action).put("event",java.util.UUID.randomUUID().toString())
        if(muted!=null) value.put("muted",muted)
        prefs(c).edit().putString("call-event",value.toString()).commit()
    }
    fun open(c:Context,id:String) {
        if(current(c)?.optString("id")!=id) return
        c.startActivity(Intent(c,IncomingCallActivity::class.java).putExtra("answer",true).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
    fun refresh(c:Context) { c.startService(Intent(c,IncomingCallService::class.java)) }
    fun reject(c:Context,id:String) {
        val call=current(c)?.takeIf { it.optString("id")==id } ?: return
        event(c,call,"decline")
        Thread {
            try {
                val endpoint=prefs(c).getString("call-endpoint",null) ?: return@Thread
                val url=URL(endpoint.trimEnd('/')+"/v1/routes/"+call.getString("registration")+"/calls/"+id)
                if(url.protocol!="https") return@Thread
                val request=url.openConnection() as HttpURLConnection
                request.instanceFollowRedirects=false;request.connectTimeout=2000;request.readTimeout=2000;request.requestMethod="DELETE"
                request.setRequestProperty("Authorization","Bearer "+call.getString("ticket"))
                try { request.responseCode } finally { request.disconnect() }
            } catch (_:Exception) { /* The remote ring also has a bounded deadline. */ }
        }.start()
        finish(c,id)
    }
    fun answer(c: Context,id: String) {
        val call=current(c)?.takeIf { it.optString("id")==id && it.optLong("expires")>System.currentTimeMillis()/1000 } ?: return
        call.put("action","answer");save(c,call)
        refresh(c)
    }
    fun connected(c: Context,id: String) {
        val call=current(c)?.takeIf { it.optString("id")==id } ?: return
        call.put("connected",true).put("action","connected");save(c,call)
        EloConnectionService.connection?.setActive()
        refresh(c)
    }
    fun silence(c:Context) {
        current(c)?.let { call -> call.put("silenced",true);save(c,call);refresh(c) }
    }
}

class EloConnectionService: ConnectionService() {
    companion object { var connection: Connection?=null }
    override fun onCreateIncomingConnection(manager: PhoneAccountHandle?, request: ConnectionRequest?): Connection {
        val call=IncomingCalls.current(this) ?: return Connection.createFailedConnection(DisconnectCause(DisconnectCause.ERROR))
        val id=call.optString("id")
        val result=object:Connection() {
            private var lastMuted=false
            override fun onShowIncomingCallUi() {
                val intent=Intent(this@EloConnectionService,IncomingCallService::class.java)
                if(Build.VERSION.SDK_INT>=26) startForegroundService(intent) else startService(intent)
            }
            override fun onReject() { IncomingCalls.reject(this@EloConnectionService,id) }
            override fun onDisconnect() { IncomingCalls.reject(this@EloConnectionService,id) }
            override fun onAnswer() { IncomingCalls.open(this@EloConnectionService,id) }
            override fun onAnswer(videoState:Int) { onAnswer() }
            override fun onSilence() { IncomingCalls.silence(this@EloConnectionService) }
            override fun onCallAudioStateChanged(state:CallAudioState) {
                if(lastMuted==state.isMuted) return
                lastMuted=state.isMuted
                IncomingCalls.current(this@EloConnectionService)?.takeIf { it.optBoolean("connected") }?.let {
                    IncomingCalls.event(this@EloConnectionService,it,"mute",state.isMuted)
                }
            }
        }
        result.connectionProperties=Connection.PROPERTY_SELF_MANAGED
        result.setAudioModeIsVoip(true)
        result.setCallerDisplayName("elo.now",TelecomManager.PRESENTATION_ALLOWED)
        result.setRinging();connection=result
        return result
    }
    override fun onCreateIncomingConnectionFailed(manager:PhoneAccountHandle?,request:ConnectionRequest?) {
        IncomingCalls.current(this)?.optString("id")?.let { IncomingCalls.finish(this,it) }
    }
    override fun onConnectionServiceFocusLost() {
        IncomingCalls.silence(this)
        connectionServiceFocusReleased()
    }
}

class IncomingCallService: Service() {
    private val handler=Handler(Looper.getMainLooper())
    private var checking=false
    private val ringer by lazy { IncomingCallRinger(this) }
    private fun updateRingtone(call: JSONObject?) {
        val tone=IncomingCalls.prefs(this).getString("call-ringtone","classic") ?: "classic"
        val ringing=call?.optString("action")=="ring" && !call.optBoolean("silenced") && call.optLong("expires")>System.currentTimeMillis()/1000
        ringer.update(if(ringing) call?.optString("id") else null,tone,"elo_calls_loop_$tone")
    }
    override fun onBind(intent:Intent?) = null
    override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int {
        val call=IncomingCalls.current(this) ?: run { stopSelf();return START_NOT_STICKY }
        val p=IncomingCalls.prefs(this)
        val tone=p.getString("call-ringtone","classic") ?: "classic"
        val ringing=call.optString("action")=="ring"
        val channel=if(ringing) "elo_calls_loop_$tone" else "elo_calls_active"
        if(Build.VERSION.SDK_INT>=26) {
            val settings=NotificationChannel(channel,IncomingCalls.label(this,"incoming"),NotificationManager.IMPORTANCE_HIGH)
            // The service owns looping audio; the notification must not play it twice.
            settings.setSound(null,null)
            settings.enableVibration(ringing && tone!="silent")
            getSystemService(NotificationManager::class.java).createNotificationChannel(settings)
        }
        val id=call.optString("id")
        fun open(answer:Boolean)=PendingIntent.getActivity(this,if(answer)71003 else 71004,
            Intent(this,IncomingCallActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).setData(Uri.parse("elo-call://$id")).putExtra("answer",answer),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val reject=PendingIntent.getBroadcast(this,71005,Intent(this,DeclineCallReceiver::class.java).putExtra("id",id),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val person=Person.Builder().setName("elo.now").setImportant(true).build()
        val builder=NotificationCompat.Builder(this,channel)
            .setSmallIcon(R.drawable.ic_elo_notification).setContentTitle("elo.now")
            .setContentText(IncomingCalls.label(this,if(ringing) "incoming" else if(call.optBoolean("connected")) "connected" else "unlock"))
            .setCategory(NotificationCompat.CATEGORY_CALL).setPriority(NotificationCompat.PRIORITY_MAX)
            .setOngoing(true).setContentIntent(open(!ringing)).setOnlyAlertOnce(true)
        if(ringing) {
            builder.setTimeoutAfter((call.optLong("expires")*1000-System.currentTimeMillis()).coerceAtLeast(1))
                .setFullScreenIntent(open(false),true)
                .setStyle(NotificationCompat.CallStyle.forIncomingCall(person,reject,open(true)))
        } else builder.setSilent(true).setStyle(NotificationCompat.CallStyle.forOngoingCall(person,reject))
        startForeground(71002,builder.build())
        updateRingtone(call)
        handler.removeCallbacksAndMessages(null);handler.post(tick)
        return START_NOT_STICKY
    }
    private val tick=object:Runnable {
        override fun run() {
            val call=IncomingCalls.current(this@IncomingCallService) ?: run { ringer.stop();stopSelf();return }
            updateRingtone(call)
            if(!call.optBoolean("connected")) {
                if(call.optLong("expires")<=System.currentTimeMillis()/1000) { IncomingCalls.finish(this@IncomingCallService,call.optString("id"));return }
                if(!checking && call.optString("action")!="answer") {
                    checking=true
                    Thread {
                        var ended=false
                        try {
                            val endpoint=IncomingCalls.prefs(this@IncomingCallService).getString("call-endpoint",null) ?: throw IllegalStateException()
                            val url=URL(endpoint.trimEnd('/')+"/v1/routes/"+call.getString("registration")+"/calls/"+call.getString("id"))
                            if(url.protocol!="https") throw IllegalStateException()
                            val request=url.openConnection() as HttpURLConnection
                            request.instanceFollowRedirects=false;request.connectTimeout=2000;request.readTimeout=2000
                            request.setRequestProperty("Authorization","Bearer "+call.getString("ticket"))
                            try {
                                ended=request.responseCode==410
                                if(request.responseCode==200) {
                                    val body=request.inputStream.use { input -> val bytes=ByteArray(1025);var used=0;while(used<bytes.size) { val n=input.read(bytes,used,bytes.size-used);if(n<0) break;used+=n };String(bytes,0,used) }
                                    if(body.length<=1024) ended=!JSONObject(body).optBoolean("ringing",false)
                                }
                            } finally { request.disconnect() }
                        } catch (_: Exception) { /* Local expiry remains authoritative when offline. */ }
                        handler.post { checking=false;if(ended && IncomingCalls.current(this@IncomingCallService)?.optString("action")=="ring") IncomingCalls.finish(this@IncomingCallService,call.optString("id")) }
                    }.start()
                }
            }
            handler.postDelayed(this,2000)
        }
    }
    override fun onDestroy() { ringer.stop();handler.removeCallbacksAndMessages(null);super.onDestroy() }
}
class DeclineCallReceiver:BroadcastReceiver() {
    override fun onReceive(c:Context,intent:Intent) { intent.getStringExtra("id")?.let { IncomingCalls.reject(c,it) } }
}
class IncomingCallActivity:Activity() {
    private val handler=Handler(Looper.getMainLooper())
    private val expiry=object:Runnable {
        override fun run() {
            if(IncomingCalls.current(this@IncomingCallActivity)==null) finishAndRemoveTask()
            else handler.postDelayed(this,500)
        }
    }
    override fun onDestroy() { handler.removeCallbacksAndMessages(null);super.onDestroy() }
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        if(Build.VERSION.SDK_INT>=27) { setShowWhenLocked(true);setTurnScreenOn(true) }
        else window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or android.view.WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)
        val call=IncomingCalls.current(this) ?: run { finish();return }
        val id=call.optString("id")
        setContentView(incomingCallScreen(
            answer = { answer(id) },
            decline = { IncomingCalls.reject(this, id); finishAndRemoveTask() },
        ))
        handler.post(expiry)
        if(call.optBoolean("connected")) { launchApp();return }
        if(intent.getBooleanExtra("answer",false)) answer(id)
    }
    private fun launchApp() {
        val intent=packageManager.getLaunchIntentForPackage(packageName) ?: return
        intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        startActivity(intent);finishAndRemoveTask()
    }
    private fun answer(id:String) {
        fun launch() {
            IncomingCalls.answer(this,id)
            launchApp()
        }
        val keyguard=getSystemService(KeyguardManager::class.java)
        if(Build.VERSION.SDK_INT>=26 && keyguard.isKeyguardLocked) keyguard.requestDismissKeyguard(this,object:KeyguardManager.KeyguardDismissCallback() { override fun onDismissSucceeded() { launch() } }) else launch()
    }
}
