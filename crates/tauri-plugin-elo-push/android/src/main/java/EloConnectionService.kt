package now.elo.push

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.OutcomeReceiver
import android.telecom.CallAudioState
import android.telecom.CallEndpoint
import android.telecom.CallEndpointException
import android.telecom.Connection
import android.telecom.ConnectionRequest
import android.telecom.ConnectionService
import android.telecom.DisconnectCause
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import androidx.annotation.RequiresApi
import app.tauri.plugin.JSObject
import org.json.JSONArray
import org.json.JSONObject

class EloConnectionService : ConnectionService() {
    override fun onCreateOutgoingConnection(account: PhoneAccountHandle?, request: ConnectionRequest): Connection =
        OutgoingCalls.create(this, request.extras) ?: Connection.createFailedConnection(DisconnectCause(DisconnectCause.CANCELED))
    override fun onCreateOutgoingConnectionFailed(account: PhoneAccountHandle?, request: ConnectionRequest) {
        OutgoingCalls.failed(request.extras)
    }
    override fun onCreateIncomingConnection(account: PhoneAccountHandle?, request: ConnectionRequest): Connection {
        return IncomingCalls.createConnection(this, request.extras?.getString(IncomingCalls.CALL_ID), request.extras?.getString(IncomingCalls.INVITATION_ID))
            ?: Connection.createFailedConnection(DisconnectCause(DisconnectCause.CANCELED))
    }
    override fun onCreateIncomingConnectionFailed(account: PhoneAccountHandle?, request: ConnectionRequest) {
        IncomingCalls.initialize(this)
        IncomingCalls.reject(request.extras?.getString(IncomingCalls.CALL_ID) ?: "", request.extras?.getString(IncomingCalls.INVITATION_ID) ?: "", "unavailable")
    }
}

internal class EloConnection(private val context: Context, val offer: IncomingCallState.Offer) :
    EloAudioConnection(context, offer.callId, context.getString(R.string.notification_incoming_call)) {
    init { setRinging() }
    fun matches(id: String, invitation: String) = offer.callId == id && offer.invitationId == invitation
    override fun ownsConnection() = IncomingCalls.ownsTelecom(offer)
    override fun systemMute(muted: Boolean) {
        IncomingCalls.systemMute(offer, muted)
    }
    override fun onShowIncomingCallUi() { IncomingCalls.showIncoming(offer.callId, offer.invitationId) }
    override fun onAnswer() { IncomingCalls.answer(offer.callId, offer.invitationId) }
    override fun onAnswer(videoState: Int) { onAnswer() }
    override fun onReject() { IncomingCalls.rejectFromSystem(offer.callId, offer.invitationId) }
    override fun onDisconnect() { IncomingCalls.end(offer.callId, offer.invitationId) }
    override fun onAbort() { IncomingCalls.end(offer.callId, offer.invitationId) }
    override fun onSilence() { IncomingCallService.silence(context, offer) }
}

internal abstract class EloAudioConnection(private val context: Context, callId: String, name: String) : Connection() {
    private var endpoints: List<CallEndpoint> = emptyList()
    private var endpoint: CallEndpoint? = null
    private var muted = false
    @Suppress("DEPRECATION")
    private var legacyAudio: CallAudioState? = null
    init {
        connectionProperties = PROPERTY_SELF_MANAGED
        connectionCapabilities = CAPABILITY_MUTE
        audioModeIsVoip = true
        setAddress(Uri.fromParts("elo", callId, null), TelecomManager.PRESENTATION_RESTRICTED)
        setCallerDisplayName(name, TelecomManager.PRESENTATION_ALLOWED)
    }
    protected abstract fun ownsConnection(): Boolean
    protected abstract fun systemMute(muted: Boolean)
    fun microphoneMuted() = muted
    @RequiresApi(34)
    override fun onAvailableCallEndpointsChanged(availableEndpoints: MutableList<CallEndpoint>) {
        if (!ownsConnection()) return
        endpoints = availableEndpoints.toList()
        ChatSessionAudio.telecomChanged()
    }
    @RequiresApi(34)
    override fun onCallEndpointChanged(callEndpoint: CallEndpoint) {
        if (!ownsConnection()) return
        endpoint = callEndpoint
        ChatSessionAudio.telecomChanged()
    }
    @RequiresApi(34)
    override fun onMuteStateChanged(isMuted: Boolean) {
        if (!ownsConnection()) return
        if (muted != isMuted) { muted = isMuted; systemMute(muted) }
        ChatSessionAudio.telecomChanged()
    }
    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onCallAudioStateChanged(state: CallAudioState) {
        if (!ownsConnection()) return
        legacyAudio = state
        if (muted != state.isMuted) { muted = state.isMuted; systemMute(muted) }
        ChatSessionAudio.telecomChanged()
    }
    fun route(outputId: String?, completed: (JSObject?, String?) -> Unit) {
        if (!ownsConnection()) { completed(null, "unavailable"); return }
        if (Build.VERSION.SDK_INT >= 34) modernRoute(outputId, completed)
        else legacyRoute(outputId, completed)
    }
    @RequiresApi(34)
    private fun modernRoute(outputId: String?, completed: (JSObject?, String?) -> Unit) {
        if (outputId == null) { completed(modernValue(), null); return }
        val requested = endpoints.firstOrNull { it.identifier.toString() == outputId }
        if (requested == null) { completed(null, "unavailable"); return }
        requestCallEndpointChange(requested, context.mainExecutor, object : OutcomeReceiver<Void, CallEndpointException> {
            override fun onResult(result: Void?) { if (ownsConnection()) completed(modernValue(), null) else completed(null, "unavailable") }
            override fun onError(error: CallEndpointException) { completed(null, "unavailable") }
        })
    }
    @RequiresApi(34)
    private fun modernValue(): JSObject = JSObject().put("selected", endpoint?.identifier?.toString() ?: JSONObject.NULL)
        .put("muted", muted).put("outputs", JSONArray(endpoints.map { value ->
            val kind = when (value.endpointType) {
                CallEndpoint.TYPE_EARPIECE -> "receiver"
                CallEndpoint.TYPE_SPEAKER -> "speaker"
                CallEndpoint.TYPE_BLUETOOTH -> "bluetooth"
                CallEndpoint.TYPE_WIRED_HEADSET -> "headphones"
                else -> "system"
            }
            JSObject().put("id", value.identifier.toString()).put("kind", kind).also {
                if (kind !in listOf("receiver", "speaker")) it.put("name", value.endpointName.toString().take(120))
            }
        }))
    @Suppress("DEPRECATION")
    private fun legacyRoute(outputId: String?, completed: (JSObject?, String?) -> Unit) {
        val audio = legacyAudio ?: run { completed(null, "unavailable"); return }
        val routes = listOf("receiver" to CallAudioState.ROUTE_EARPIECE, "speaker" to CallAudioState.ROUTE_SPEAKER,
            "bluetooth" to CallAudioState.ROUTE_BLUETOOTH, "headphones" to CallAudioState.ROUTE_WIRED_HEADSET)
            .filter { audio.supportedRouteMask and it.second != 0 }
        if (outputId != null) {
            val route = routes.firstOrNull { it.first == outputId } ?: run { completed(null, "unavailable"); return }
            setAudioRoute(route.second)
        }
        completed(JSObject().put("selected", routes.firstOrNull { it.second == audio.route }?.first ?: JSONObject.NULL)
            .put("muted", audio.isMuted).put("outputs", JSONArray(routes.map { JSObject().put("id", it.first).put("kind", it.first) })), null)
    }
}
