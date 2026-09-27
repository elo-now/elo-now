package now.elo.push

import android.content.Context
import android.net.Uri
import android.telecom.DisconnectCause
import androidx.core.telecom.CallAttributesCompat
import androidx.core.telecom.CallControlResult
import androidx.core.telecom.CallControlScope
import androidx.core.telecom.CallsManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Process-owned call lifetime; navigating or unlocking must not destroy Telecom's call. */
internal object TelecomCalls {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private class Session(val id: String) {
        var control: CallControlScope? = null
        val state = TelecomCallState()
        var job: kotlinx.coroutines.Job? = null
    }
    @Volatile private var session: Session? = null

    fun hasCall(id: String): Boolean = session?.let { it.id == id && !it.state.ended } == true

    fun isReady(id: String): Boolean = session?.let {
        it.id == id && it.state.ready && !it.state.ended
    } == true

    fun incoming(context: Context, id: String) {
        val app = context.applicationContext
        scope.launch {
            if (IncomingCalls.current(app)?.optString("id") != id) return@launch
            val current = Session(id)
            session = current
            current.job = coroutineContext[kotlinx.coroutines.Job]
            try {
                val manager = CallsManager(app)
                manager.registerAppWithTelecom(CallsManager.CAPABILITY_SUPPORTS_VIDEO_CALLING)
                manager.addCall(
                    CallAttributesCompat(
                        displayName = "elo.now",
                        // No profile name or encrypted destination is exposed to Telecom.
                        address = Uri.parse("elo-call:$id"),
                        direction = CallAttributesCompat.DIRECTION_INCOMING,
                        callType = CallAttributesCompat.CALL_TYPE_AUDIO_CALL,
                        callCapabilities = 0,
                    ),
                    onAnswer = {
                        if (!current.state.ended) {
                            current.state.answeredBySystem = true
                            IncomingCalls.open(app, id)
                        }
                    },
                    onDisconnect = {
                        current.state.systemDisconnected()
                        IncomingCalls.reject(app, id)
                    },
                    onSetActive = { },
                    // Hold is not advertised: do not acknowledge a media pause we cannot perform.
                    onSetInactive = { throw UnsupportedOperationException("Call hold is not supported") },
                ) {
                    current.control = this
                    current.state.ready = true
                    if (current.state.ended || IncomingCalls.current(app)?.optString("id") != id) {
                        current.state.ended = true
                        applyState(app, current)
                    } else {
                        app.startForegroundService(IncomingCalls.serviceIntent(app, id))
                        applyState(app, current)
                        launch {
                            var lastMuted = false
                            isMuted.collect { muted ->
                                if (muted == lastMuted) return@collect
                                lastMuted = muted
                                IncomingCalls.current(app)?.takeIf {
                                    it.optString("id") == id && it.optBoolean("connected")
                                }?.let { IncomingCalls.event(app, it, "mute", muted) }
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                // End the app-side call as well; never leave a Connecting call without Telecom.
                IncomingCalls.reject(app, id)
            } finally {
                if (session === current) session = null
                IncomingCalls.finish(app, id)
            }
        }
    }

    fun connected(context: Context, id: String) {
        scope.launch {
            val current = session?.takeIf { it.id == id && !it.state.ended } ?: return@launch
            current.state.connected = true
            applyState(context.applicationContext, current)
        }
    }

    private fun applyState(context: Context, current: Session) {
        val control = current.control ?: return
        val command = current.state.nextCommand() ?: return
        scope.launch {
            if (command == TelecomCallState.Command.ANSWER && current.state.ended) return@launch
            val success = try {
                when (command) {
                    TelecomCallState.Command.ANSWER -> control.answer(CallAttributesCompat.CALL_TYPE_AUDIO_CALL)
                    TelecomCallState.Command.DISCONNECT -> control.disconnect(DisconnectCause(DisconnectCause.LOCAL))
                } is CallControlResult.Success
            } catch (_: Exception) { false }
            if (!success) {
                IncomingCalls.reject(context, current.id)
                if (command == TelecomCallState.Command.DISCONNECT) current.job?.cancel()
            }
        }
    }

    fun end(context: Context, id: String) {
        scope.launch {
            val current = session?.takeIf { it.id == id } ?: return@launch
            current.state.ended = true
            applyState(context.applicationContext, current)
        }
    }
}
