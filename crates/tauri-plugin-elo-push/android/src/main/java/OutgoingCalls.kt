package now.elo.push

import android.app.Activity
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.telecom.DisconnectCause
import android.telecom.TelecomManager
import app.tauri.plugin.JSObject
import org.json.JSONObject

/** Telecom presentation for media admitted by Rust, never a push or a restored intent. */
@android.annotation.SuppressLint("StaticFieldLeak") // Application context only; the connection is cleared when its lease ends.
internal object OutgoingCalls {
    const val MEDIA_ID = "elo_media_id"
    const val ACTIVATION = "elo_activation"
    private val state = OutgoingCallState()
    private val main = Handler(Looper.getMainLooper())
    private var context: Context? = null
    private var connection: OutgoingConnection? = null
    private val pending = mutableListOf<(JSObject) -> Unit>()
    private var name = "elo.now"

    fun start(activity: Activity, request: JSONObject, completed: (JSObject) -> Unit) {
        checkMain()
        val lease = OutgoingCallState.Lease(request.getString("id"), request.getString("call_id"), request.getString("activation"))
        check(ChatSessions.state.active()?.id == lease.callId && ChatSessionAudio.owns(lease.callId, lease.activation)) { "ended" }
        if (IncomingCalls.authorizedMedia(lease.mediaId) && IncomingCalls.authorizedCallMedia(lease.callId) == lease.mediaId) {
            completed(JSObject()); return
        }
        val fresh = state.begin(lease)
        if (!fresh && connection != null) { completed(JSObject()); return }
        check(pending.size < 4) { "unavailable" }
        pending += completed
        if (!fresh) return
        context = activity.applicationContext
        name = request.optString("name", "elo.now").take(120).filterNot(Char::isISOControl).ifBlank { "elo.now" }
        val value = checkNotNull(context)
        try {
            val telecom = value.getSystemService(TelecomManager::class.java)
            val account = IncomingCalls.registerAccount(value)
            check(telecom.isOutgoingCallPermitted(account)) { "unavailable" }
            telecom.placeCall(Uri.fromParts("elo", lease.callId, null), Bundle().apply {
                putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, account)
                putBundle(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS, Bundle().apply {
                    putString(MEDIA_ID, lease.mediaId)
                    putString(IncomingCalls.CALL_ID, lease.callId)
                    putString(ACTIVATION, lease.activation)
                })
            })
            main.postDelayed({
                if (state.owns(lease) && connection == null) failed(lease)
            }, 5_000)
        } catch (_: SecurityException) { failed(lease) }
        catch (_: RuntimeException) { failed(lease) }
    }
    fun create(context: Context, extras: Bundle?): OutgoingConnection? {
        checkMain()
        val lease = lease(extras) ?: return null
        if (!state.owns(lease) || connection != null || !ChatSessionAudio.owns(lease.callId, lease.activation)) return null
        return OutgoingConnection(context.applicationContext, lease, name).also {
            connection = it
            ChatSessionAudio.adoptTelecom(lease.callId, lease.activation)
            // Telecom must receive the Connection before it becomes active or
            // Rust continues the media setup that may report it connected.
            main.post {
                if (state.owns(lease) && connection === it) {
                    if (state.isConnected(lease)) it.setActive()
                    pending.toList().also { pending.clear() }.forEach { callback -> callback(JSObject()) }
                    IncomingCalls.refreshPresentation()
                }
            }
        }
    }
    fun failed(extras: Bundle?) { lease(extras)?.let(::failed) }
    private fun failed(lease: OutgoingCallState.Lease) { finish(lease, true, "unavailable") }
    fun connected(id: String) {
        checkMain()
        val lease = state.active()?.takeIf { it.mediaId == id } ?: return
        if (state.connected(lease)) connection?.setActive()
    }
    fun end(id: String) {
        checkMain()
        state.active()?.takeIf { it.mediaId == id }?.let { finish(it, false, "ended") }
    }
    fun userEnd(lease: OutgoingCallState.Lease) { finish(lease, true, "ended") }
    private fun finish(lease: OutgoingCallState.Lease, notify: Boolean, error: String) {
        checkMain()
        if (!state.end(lease)) return
        connection?.apply { setDisconnected(DisconnectCause(DisconnectCause.LOCAL)); destroy() }
        connection = null
        pending.toList().also { pending.clear() }.forEach { it(JSObject().put("error", error)) }
        if (notify) {
            ChatSessionAudio.systemAction(lease.callId, lease.activation, "end")
            NativeMedia.stop(lease.mediaId)
            if (ChatSessionAudio.owns(lease.callId, lease.activation)) context?.let { ChatSessions.stop(it, lease.callId) }
        }
        IncomingCalls.refreshPresentation()
    }
    fun mute(lease: OutgoingCallState.Lease, muted: Boolean) {
        if (!state.owns(lease)) return
        val revision = NativeMedia.telecomMute(lease.mediaId) ?: return
        ChatSessionAudio.systemAction(lease.callId, lease.activation, "mute", muted, revision)
    }
    fun owns(lease: OutgoingCallState.Lease) = state.owns(lease)
    fun owns(id: String) = connection?.lease?.let { it.callId == id && state.owns(it) } == true
    fun active() = state.active() != null
    fun authorizedMedia(id: String) = connection?.lease?.let {
        it.mediaId == id && state.owns(it) && ChatSessionAudio.owns(it.callId, it.activation)
    } == true
    fun muted(id: String) = connection?.takeIf { it.lease.mediaId == id && state.owns(it.lease) }?.microphoneMuted() == true
    fun route(id: String, outputId: String?, completed: (JSObject?, String?) -> Unit) {
        connection?.takeIf { it.lease.callId == id && state.owns(it.lease) }?.route(outputId, completed) ?: completed(null, "unavailable")
    }
    private fun lease(extras: Bundle?): OutgoingCallState.Lease? {
        val values = extras?.getBundle(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS) ?: extras ?: return null
        return OutgoingCallState.Lease(values.getString(MEDIA_ID) ?: return null,
            values.getString(IncomingCalls.CALL_ID) ?: return null, values.getString(ACTIVATION) ?: return null)
    }
    private fun checkMain() { check(Looper.myLooper() == Looper.getMainLooper()) }
}

internal class OutgoingConnection(context: Context, val lease: OutgoingCallState.Lease, name: String) : EloAudioConnection(context, lease.callId, name) {
    init { setDialing() }
    override fun ownsConnection() = OutgoingCalls.owns(lease)
    override fun systemMute(muted: Boolean) { OutgoingCalls.mute(lease, muted) }
    override fun onDisconnect() { OutgoingCalls.userEnd(lease) }
    override fun onAbort() { OutgoingCalls.userEnd(lease) }
}
