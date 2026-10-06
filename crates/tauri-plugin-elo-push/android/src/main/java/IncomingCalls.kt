package now.elo.push

import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.telecom.DisconnectCause
import android.telecom.PhoneAccount
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import androidx.core.content.ContextCompat
import app.tauri.plugin.JSObject
import org.json.JSONArray
import org.json.JSONObject

/** Only opaque call targets are persisted here. Profile keys never enter this store. */
@android.annotation.SuppressLint("StaticFieldLeak") // Only the application context is retained.
internal object IncomingCalls {
    const val CALL_ID = "elo_call_id"
    const val INVITATION_ID = "elo_invitation_id"
    const val SHOW = "now.elo.push.SHOW_INCOMING_CALL"
    const val ANSWER = "now.elo.push.ANSWER_INCOMING_CALL"
    const val DECLINE = "now.elo.push.DECLINE_INCOMING_CALL"
    const val END = "now.elo.push.END_INCOMING_CALL"
    const val NOTIFICATION_ID = 71003
    private const val STORE = "native-incoming-v1"
    private val main = Handler(Looper.getMainLooper())
    private val state = IncomingCallState()
    private var context: Context? = null
    private var listener: ((JSObject) -> Unit)? = null
    private val connections = linkedMapOf<String, EloConnection>()
    private val presentedKeys = mutableSetOf<String>()
    private val submittedKeys = mutableSetOf<String>()
    private var authorizedMedia: Pair<String, String>? = null
    private var activity = java.lang.ref.WeakReference<IncomingCallActivity>(null)
    private val expiry = Runnable { expire() }

    fun receive(context: Context, data: Map<String, String>) {
        if (data["elo_ring"] != "1") return
        val offer = IncomingCallState.Offer(data[CALL_ID] ?: "", data[INVITATION_ID] ?: "",
            data["elo_registration"] ?: "", data["elo_target"] ?: "", data["elo_expires"]?.toLongOrNull() ?: 0)
        main.post { initialize(context); report(offer) }
    }

    fun initialize(value: Context) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (context != null) return
        context = value.applicationContext
        val prefs = value.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
        runCatching {
            val json = JSONObject(prefs.getString(STORE, null) ?: return@runCatching)
            val pending = json.optJSONArray("pending") ?: JSONArray()
            val seen = json.optJSONObject("seen") ?: JSONObject()
            fun restoredCall(key: String) = json.optJSONObject(key)?.let {
                IncomingCallState.Call(offer(it), IncomingCallState.Phase.valueOf(it.getString("phase")), it.getLong("deadline"))
            }
            val call = restoredCall("call")
            state.restore(IncomingCallState.Snapshot(call, (0 until pending.length()).map { index ->
                val event = pending.getJSONObject(index)
                IncomingCallState.Event(event.getString("eventId"), event.getString("action"), offer(event), event.getLong("createdAt"), event.optString("reason").takeIf { it.isNotEmpty() })
            }, seen.keys().asSequence().associateWith { seen.getLong(it) }, restoredCall("waiting")), System.currentTimeMillis())
        }.onFailure { prefs.edit().remove(STORE).commit() }
        // An old notification may outlive its process. It has no authority to
        // capture audio, and can be replaced only by a fresh Telecom connection.
        render()
        state.calls().forEach { submit(it.offer) }
    }

    fun listen(value: Context, callback: ((JSObject) -> Unit)?) {
        initialize(value)
        listener = callback
        publish()
    }

    fun status(value: Context): JSObject {
        initialize(value)
        expire()
        return statusValue()
    }

    fun command(value: Context, payload: JSONObject): JSObject {
        initialize(value)
        val id = payload.optString("callId")
        val invitation = payload.optString("invitationId")
        when (payload.getString("op")) {
            "report" -> report(offer(payload))
            "authorize" -> {
                val mediaId = payload.getString("mediaId")
                check(state.authorize(id, invitation, mediaId, System.currentTimeMillis())) { "incoming_call_expired" }
                authorizedMedia = checkNotNull(state.matching(id, invitation)).offer.key to mediaId
            }
            "connected" -> {
                check(authorizedMedia?.first == state.matching(id, invitation)?.offer?.key && authorizedMedia != null) { "incoming_call_unauthorized" }
                check(state.connected(id, invitation, System.currentTimeMillis())) { "incoming_call_expired" }
                connections.values.firstOrNull { it.matches(id, invitation) }?.setActive()
                render()
            }
            "ended", "answer_failed" -> {
                state.end(id, invitation, "", payload.optString("reason"), System.currentTimeMillis())
                render()
            }
            "ack" -> { state.ack(payload.getString("eventId")); persist() }
            "status" -> expire()
            else -> error("invalid_incoming_call_operation")
        }
        return statusValue()
    }

    private fun report(offer: IncomingCallState.Offer) {
        val value = checkNotNull(context)
        val prefs = value.getSharedPreferences("elo-push", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("enabled", false) || !PushRegistrations.contains(prefs, offer.registration)) return
        if (state.receive(offer, System.currentTimeMillis())) {
            persist()
            submit(offer)
        }
        render()
    }

    @Suppress("DEPRECATION") // ConnectionService supports the existing API 27 minimum.
    private fun submit(offer: IncomingCallState.Offer) {
        if (offer.key in submittedKeys) return
        val value = checkNotNull(context)
        try {
            val telecom = value.getSystemService(TelecomManager::class.java)
            val handle = registerAccount(value)
            if (!telecom.isIncomingCallPermitted(handle)) {
                reject(offer.callId, offer.invitationId, "unavailable")
                return
            }
            submittedKeys += offer.key
            telecom.addNewIncomingCall(handle, Bundle().apply {
                putString(CALL_ID, offer.callId)
                putString(INVITATION_ID, offer.invitationId)
            })
        } catch (_: RuntimeException) {
            reject(offer.callId, offer.invitationId, "unavailable")
        }
    }

    fun createConnection(value: Context, id: String?, invitation: String?): EloConnection? {
        initialize(value)
        expire()
        val call = state.matching(id ?: return null, invitation ?: return null) ?: return null
        if (call.offer.key in connections) return null
        return EloConnection(value.applicationContext, call.offer).also { connections[call.offer.key] = it }
    }

    fun showIncoming(id: String, invitation: String) {
        val call = state.matching(id, invitation) ?: return
        if (call.phase != IncomingCallState.Phase.RINGING || call.offer.key in presentedKeys) return
        presentedKeys += call.offer.key
        val value = checkNotNull(context)
        try {
            ContextCompat.startForegroundService(value, Intent(value, IncomingCallService::class.java).apply {
                action = SHOW; putExtra(CALL_ID, id); putExtra(INVITATION_ID, invitation)
            })
        } catch (_: RuntimeException) {
            reject(id, invitation, "unavailable")
        }
        publish()
    }

    fun answer(id: String, invitation: String, openApp: Boolean = true) {
        if (!state.answer(id, invitation, System.currentTimeMillis())) { render(); return }
        // setActive is deliberately deferred until Rust confirms media readiness.
        context?.let { IncomingCallService.silence(it) }
        render()
        if (openApp) openApplication()
    }

    fun reject(id: String, invitation: String, reason: String = "declined") {
        state.end(id, invitation, "decline", reason, System.currentTimeMillis())
        render()
    }

    fun rejectFromSystem(id: String, invitation: String) {
        reject(id, invitation)
        val value = context ?: return
        if (pendingDecline(id, invitation) == null) return
        // Use one bounded cold transport for notification, lock-screen and
        // Bluetooth/Telecom rejection, without opening the profile Activity.
        value.sendBroadcast(Intent(value, IncomingCallReceiver::class.java).apply {
            action = DECLINE; putExtra(CALL_ID, id); putExtra(INVITATION_ID, invitation)
        })
    }

    fun end(id: String, invitation: String) {
        state.end(id, invitation, "end", "local", System.currentTimeMillis())
        render()
    }

    fun remove(value: Context, registration: String? = null) {
        initialize(value)
        state.removeRegistration(registration, System.currentTimeMillis())
        render()
    }

    fun active(): IncomingCallState.Call? = state.active()
    fun calls(): List<IncomingCallState.Call> = state.calls()
    fun matching(id: String?, invitation: String?) = if (id == null || invitation == null) null else state.matching(id, invitation)
    fun hasOtherOngoing(id: String, invitation: String) = state.calls().any {
        it.phase == IncomingCallState.Phase.CONNECTED && (it.offer.callId != id || it.offer.invitationId != invitation)
    }
    fun pendingDecline(id: String, invitation: String): JSObject? = state.pending().lastOrNull {
        it.action == "decline" && it.offer.callId == id && it.offer.invitationId == invitation
    }?.let(::eventJson)
    fun authorizedMedia(id: String): Boolean = state.authorizedCall(id, System.currentTimeMillis())?.let {
        connections.containsKey(it.offer.key)
    } == true
    fun authorizedCallMedia(id: String): String? = authorizedMedia?.second?.takeIf { media ->
        state.authorizedCall(media, System.currentTimeMillis())?.offer?.callId == id && authorizedMedia(media)
    }
    fun systemMute(offer: IncomingCallState.Offer, muted: Boolean) {
        val media = authorizedMedia?.takeIf { it.first == offer.key }?.second ?: return
        if (!authorizedMedia(media)) return
        val revision = NativeMedia.telecomMute(media) ?: return
        val event = IncomingCallState.Event(java.util.UUID.randomUUID().toString(), "mute", offer, System.currentTimeMillis())
        listener?.invoke(eventJson(event).put("muted", muted).put("systemMuteRevision", revision))
    }
    fun muted(mediaId: String) = state.authorizedCall(mediaId, System.currentTimeMillis())?.let {
        connections[it.offer.key]?.microphoneMuted()
    } == true
    fun ownsTelecom(id: String): Boolean = connections.values.any { it.offer.callId == id }
    fun ownsTelecom(offer: IncomingCallState.Offer): Boolean = connections.containsKey(offer.key)
    fun route(id: String, outputId: String?, completed: (JSObject?, String?) -> Unit) {
        val media = authorizedCallMedia(id)
        val key = media?.let { state.authorizedCall(it, System.currentTimeMillis())?.offer?.key }
        connections[key]?.route(outputId, completed) ?: completed(null, "unavailable")
    }
    fun attach(value: IncomingCallActivity) { activity = java.lang.ref.WeakReference(value) }
    fun detach(value: IncomingCallActivity) { if (activity.get() === value) activity.clear() }
    fun isPresented(offer: IncomingCallState.Offer) = offer.key in presentedKeys
    fun refreshPresentation() {
        activity.get()?.refresh()
        context?.let { if (state.active() != null) IncomingCallService.refresh(it) }
    }

    private fun openApplication() {
        val value = context ?: return
        val launch = value.packageManager.getLaunchIntentForPackage(value.packageName) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        runCatching { value.startActivity(launch) }
    }
    private fun expire() { state.expire(System.currentTimeMillis()); render() }
    private fun render() {
        val value = context ?: return
        main.removeCallbacks(expiry)
        val live = state.calls()
        val liveKeys = live.mapTo(mutableSetOf()) { it.offer.key }
        val ended = connections.keys.filter { it !in liveKeys }
        ended.forEach { key ->
            connections.remove(key)?.let {
                // Only the ended owner may release audio; declining the waiting
                // invitation must not stop the current capture or its FGS.
                if (authorizedMedia?.first == key) ChatSessions.stop(value, it.offer.callId)
                it.setDisconnected(DisconnectCause(DisconnectCause.LOCAL))
                it.destroy()
            }
        }
        authorizedMedia?.takeIf { it.first !in liveKeys }?.let {
            NativeMedia.stop(it.second)
            authorizedMedia = null
        }
        submittedKeys.retainAll(liveKeys)
        presentedKeys.retainAll(liveKeys)
        if (live.isEmpty()) {
            value.stopService(Intent(value, IncomingCallService::class.java))
            value.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        } else {
            live.minOf { it.deadline }.takeIf { it != Long.MAX_VALUE }?.let {
                main.postDelayed(expiry, maxOf(1, it - System.currentTimeMillis()))
            }
            if (state.active()?.offer?.key in presentedKeys) IncomingCallService.refresh(value)
        }
        activity.get()?.refresh()
        persist()
        publish()
    }
    private fun persist() {
        val value = context ?: return
        val snapshot = state.snapshot()
        val json = JSONObject().put("pending", JSONArray(snapshot.pending.map(::eventJson)))
            .put("seen", JSONObject(snapshot.seen))
        snapshot.call?.let { json.put("call", offerJson(it.offer).put("phase", it.phase.name).put("deadline", it.deadline)) }
        snapshot.waiting?.let { json.put("waiting", offerJson(it.offer).put("phase", it.phase.name).put("deadline", it.deadline)) }
        check(value.getSharedPreferences("elo-push", Context.MODE_PRIVATE).edit().putString(STORE, json.toString()).commit()) { "incoming_call_storage_unavailable" }
    }
    private fun publish() { listener?.let { callback -> state.pending().forEach { callback(eventJson(it)) } } }
    private fun statusValue(): JSObject = JSObject().put("pending", JSONArray(state.pending().map(::eventJson)))
        .put("systemUi", state.active() != null).put("active", state.active()?.let {
            offerJson(it.offer).put("phase", it.phase.name.lowercase()).put("systemUi", true)
        } ?: JSONObject.NULL)
    private fun offer(value: JSONObject) = IncomingCallState.Offer(value.getString("callId"), value.getString("invitationId"), value.getString("registration"), value.getString("target"), value.getLong("expires"))
    private fun offerJson(offer: IncomingCallState.Offer) = JSObject().put("callId", offer.callId).put("invitationId", offer.invitationId)
        .put("registration", offer.registration).put("target", offer.target).put("expires", offer.expires)
    private fun eventJson(event: IncomingCallState.Event): JSObject = offerJson(event.offer).put("eventId", event.eventId)
        .put("action", event.action).put("createdAt", event.createdAt).put("reason", event.reason ?: JSONObject.NULL).put("systemUi", true)
    @Suppress("DEPRECATION")
    fun registerAccount(value: Context): PhoneAccountHandle {
        val handle = PhoneAccountHandle(ComponentName(value, EloConnectionService::class.java), "elo-calls-v1")
        value.getSystemService(TelecomManager::class.java).registerPhoneAccount(PhoneAccount.builder(handle, "elo.now")
            .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED).setSupportedUriSchemes(listOf("elo")).build())
        return handle
    }
}
