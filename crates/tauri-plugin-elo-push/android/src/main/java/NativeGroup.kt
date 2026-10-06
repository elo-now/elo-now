package now.elo.push

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.FrameLayout
import app.tauri.plugin.JSObject
import io.livekit.android.*
import io.livekit.android.audio.NoAudioHandler
import io.livekit.android.e2ee.BaseKeyProvider
import io.livekit.android.e2ee.E2EEOptions
import io.livekit.android.e2ee.E2EEState
import io.livekit.android.events.RoomEvent
import io.livekit.android.room.Room
import io.livekit.android.room.participant.Participant
import io.livekit.android.room.participant.VideoTrackPublishDefaults
import io.livekit.android.room.track.RemoteTrackPublication
import io.livekit.android.room.track.RemoteAudioTrack
import io.livekit.android.room.track.Track
import io.livekit.android.room.track.VideoTrack
import io.livekit.android.renderer.TextureViewRenderer
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import livekit.LivekitModels
import livekit.org.webrtc.FrameCryptorKeyDerivationAlgorithm
import livekit.org.webrtc.RendererCommon
import org.json.JSONArray
import org.json.JSONObject

/** An epoch owns one room and one raw HKDF key. No key is passed to the SFU. */
internal class NativeGroup(val id: String, private val context: Context, private val authorized: () -> Boolean) {
    private val jobs = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val operations = Mutex()
    private var room: Room? = null
    private var provider: BaseKeyProvider? = null
    private var eventJob: Job? = null
    private var epoch = 0L
    private val policy = NativeGroupPolicy()
    private var members = emptySet<String>()
    private var stopped = false
    private var failure: String? = null
    private var revision = 0
    private var media = JSONObject().put("audio_muted", true)
    private var systemMuted = false
    private var speakerMuted = false
    private val mutedCredentials = mutableSetOf<String>()
    private var webView: WebView? = null
    private var host: FrameLayout? = null
    private var oldBackground: Drawable? = null
    private val renderers = mutableMapOf<String, Pair<VideoTrack, TextureViewRenderer>>()
    private var lastTracks = ""
    private fun live() { check(!stopped && authorized()) { "ended" } }
    fun attach(web: WebView?) { clearRenderers(); webView = web }
    fun muteMicrophone(muted: Boolean) { systemMuted = muted; room?.setMicrophoneMute(muted || media.optBoolean("audio_muted", true)) }
    fun command(request: JSONObject, completed: (JSObject) -> Unit) {
        val answered = java.util.concurrent.atomic.AtomicBoolean(false)
        fun resolve(value: JSObject) { if (answered.compareAndSet(false, true)) completed(value) }
        val job = jobs.launch {
            try {
                val result = operations.withLock {
                    live()
                    when (request.getString("op")) {
                        "group_start", "group_reset" -> { connect(request); JSObject() }
                        "poll", "snapshot" -> poll()
                        "update" -> { update(request.getJSONObject("state"), request.optBoolean("speaker_muted")); JSObject() }
                        "speaker" -> {
                            val credential = request.optString("credential").takeIf { it.isNotEmpty() }
                            if (credential == null) { speakerMuted = request.optBoolean("muted"); room?.setSpeakerMute(speakerMuted) }
                            else {
                                require(policy.maySubscribe(credential, true))
                                if (request.optBoolean("muted")) mutedCredentials += credential else mutedCredentials -= credential
                                applyRemoteVolumes()
                            }
                            JSObject()
                        }
                        "render" -> { render(request.getJSONArray("frames")); JSObject() }
                        else -> error("invalid")
                    }
                }
                live(); resolve(result)
            } catch (error: Exception) {
                if (error is CancellationException) resolve(JSObject().put("error", "ended"))
                else {
                    if (request.optString("op") in listOf("group_start", "group_reset")) fail("unavailable")
                    resolve(JSObject().put("error", if (error.message == "ended") "ended" else "unavailable"))
                }
            }
        }
        job.invokeOnCompletion { if (it != null) resolve(JSObject().put("error", "ended")) }
    }
    private suspend fun connect(request: JSONObject) {
        val nextEpoch = request.getLong("epoch")
        val url = request.getString("url")
        val token = request.getString("token")
        val secret = request.getString("key")
        val participants = request.getJSONArray("participants")
        require(url.length <= 2048 && java.net.URI(url).let { it.scheme == "wss" && !it.host.isNullOrEmpty() && it.userInfo == null })
        require(token.length in 1..16384 && secret.matches(Regex("[a-f0-9]{64}")) && participants.length() in 1..256)
        val verified = (0 until participants.length()).map { participants.getString(it) }
        policy.accept(nextEpoch, secret, verified, request.getString("credential"))
        if (nextEpoch == epoch && room != null && failure == null) return
        closeRoom()
        epoch = nextEpoch; members = policy.members; failure = null
        mutedCredentials.retainAll(members)
        LiveKit.init(context)
        val keyProvider = BaseKeyProvider(ratchetSalt = "LKFrameEncryptionKey", ratchetWindowSize = 8,
            enableSharedKey = true, failureTolerance = -1, discardFrameWhenCryptorNotReady = true,
            keyDerivationAlgorithm = FrameCryptorKeyDerivationAlgorithm.HKDF)
        provider = keyProvider
        val bytes = ByteArray(32) { index -> secret.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
        try { check(keyProvider.rtcKeyProvider.setSharedKey(0, bytes)) } finally { bytes.fill(0) }
        val current = LiveKit.create(context,
            RoomOptions(adaptiveStream = true, dynacast = true, e2eeOptions = E2EEOptions(keyProvider),
                videoTrackPublishDefaults = VideoTrackPublishDefaults(simulcast = true, videoCodec = "vp8")),
            LiveKitOverrides(audioOptions = AudioOptions(audioHandler = NoAudioHandler(), disableAudioPrewarming = true,
                disableCommunicationModeWorkaround = true)))
        room = current
        current.setMicrophoneMute(true); current.setSpeakerMute(speakerMuted)
        eventJob = jobs.launch {
            current.events.events.collect { event ->
                if (room !== current || stopped || !authorized()) return@collect
                when (event) {
                    is RoomEvent.TrackE2EEStateEvent -> if (event.state !in listOf(E2EEState.NEW, E2EEState.OK, E2EEState.KEY_RATCHETED)) fail("encryption_error")
                    is RoomEvent.TrackPublished -> if (event.participant !== current.localParticipant) subscribe(current, event.participant, event.publication as? RemoteTrackPublication)
                    is RoomEvent.ParticipantConnected -> if (event.participant.identity?.value !in members) fail("unauthorized")
                    is RoomEvent.TrackSubscribed -> applyRemoteVolumes()
                    is RoomEvent.Disconnected, is RoomEvent.FailedToConnect -> if (failure == null) fail("disconnected")
                    else -> Unit
                }
                revision += 1
            }
        }
        // Inspect publication encryption and signed membership before enabling
        // subscription. A plaintext track must never play before an event check.
        withTimeout(15_000) { current.connect(url, token, ConnectOptions(autoSubscribe = false, audio = false, video = false)) }
        live(); check(room === current && failure == null) { "ended" }
        check(current.localParticipant.identity?.value == policy.credential) { "unauthorized" }
        for (participant in current.remoteParticipants.values) {
            check(participant.identity?.value in members) { "unauthorized" }
            for (publication in participant.trackPublications.values) subscribe(current, participant, publication as? RemoteTrackPublication)
        }
        revision += 1
    }
    private fun subscribe(current: Room, participant: Participant, publication: RemoteTrackPublication?) {
        if (publication == null) return
        if (!policy.maySubscribe(participant.identity?.value, publication.encryptionType == LivekitModels.Encryption.Type.GCM)) {
            fail("encryption_error"); return
        }
        if (room === current && !stopped) publication.setSubscribed(true)
    }
    private fun applyRemoteVolumes() {
        room?.remoteParticipants?.values?.forEach { participant ->
            participant.trackPublications.values.forEach { publication ->
                (publication.track as? RemoteAudioTrack)?.setVolume(if (participant.identity?.value in mutedCredentials) 0.0 else 1.0)
            }
        }
    }
    private suspend fun publicationPermission(current: Room, source: Track.Source) {
        withTimeout(5000) {
            while (true) {
                live(); check(room === current && failure == null) { "ended" }
                val permission = current.localParticipant.permissions
                if (permission?.canPublish == true && (permission.canPublishSources.isEmpty() || source in permission.canPublishSources)) return@withTimeout
                delay(50)
            }
        }
    }
    private suspend fun update(next: JSONObject, speaker: Boolean) {
        require(!next.optBoolean("screen_published"))
        val current = checkNotNull(room) { "ended" }
        check(failure == null) { "ended" }
        val microphone = !next.optBoolean("audio_muted")
        val camera = next.optBoolean("video_published")
        if (camera != media.optBoolean("video_published")) clearRenderers()
        if (microphone) publicationPermission(current, Track.Source.MICROPHONE)
        if (camera) publicationPermission(current, Track.Source.CAMERA)
        live()
        current.setMicrophoneMute(true)
        current.localParticipant.setMicrophoneEnabled(microphone)
        live()
        current.localParticipant.setCameraEnabled(camera)
        live()
        media = JSONObject(next.toString()); speakerMuted = speaker
        current.setMicrophoneMute(systemMuted || !microphone); current.setSpeakerMute(speaker)
        revision += 1
    }
    private fun tracks(): List<Triple<Participant, io.livekit.android.room.track.TrackPublication, Track>> {
        val current = room ?: return emptyList()
        return (listOf(current.localParticipant) + current.remoteParticipants.values).flatMap { participant ->
            if (participant.identity?.value !in members) return@flatMap emptyList()
            participant.trackPublications.values.mapNotNull { publication ->
                publication.track?.takeIf { !publication.muted && publication.encryptionType == LivekitModels.Encryption.Type.GCM }
                    ?.let { Triple(participant, publication, it) }
            }
        }
    }
    private fun poll(): JSObject {
        val current = room
        val values = JSONArray(tracks().map { (participant, publication, _) ->
            JSONObject().put("id", publication.sid).put("credential", participant.identity?.value)
                .put("local", participant === current?.localParticipant).put("speaking", participant.isSpeaking)
                .put("source", when (publication.source) { Track.Source.CAMERA -> "camera"; Track.Source.SCREEN_SHARE -> "screen"; else -> "audio" })
        })
        if (values.toString() != lastTracks) { lastTracks = values.toString(); revision += 1 }
        return JSObject().put("connection", if (failure != null) "failed" else when (current?.state) {
            Room.State.CONNECTED -> "connected"; Room.State.RECONNECTING -> "disconnected"; Room.State.CONNECTING -> "connecting"; else -> "new"
        }).put("error", failure ?: JSONObject.NULL).put("revision", revision).put("signals", JSONArray()).put("tracks", values)
            .put("media", JSONObject(media.toString()).put("audio_muted", systemMuted || media.optBoolean("audio_muted", true))).put("epoch", epoch)
    }
    private fun render(frames: JSONArray) {
        require(frames.length() <= 32)
        if (frames.length() == 0) { clearRenderers(); return }
        val current = checkNotNull(room)
        val web = checkNotNull(webView)
        val parent = web.parent as? ViewGroup ?: error("unavailable")
        val available = tracks().mapNotNull { (_, publication, track) -> (track as? VideoTrack)?.let { publication.sid to it } }.toMap()
        for (index in 0 until frames.length()) {
            val frame = frames.getJSONObject(index)
            require(frame.getString("track") in available)
            val numbers = listOf("x", "y", "width", "height", "viewport_width").map { frame.getDouble(it) }
            require(numbers.all { it.isFinite() } && numbers[4] > 0 && numbers[2] in 0.0..4096.0 && numbers[3] in 0.0..4096.0 && kotlin.math.abs(numbers[0]) <= 4096 && kotlin.math.abs(numbers[1]) <= 4096)
        }
        if (host == null) {
            oldBackground = web.background
            host = FrameLayout(web.context).apply { importantForAccessibility = android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS }
            parent.addView(host, parent.indexOfChild(web), ViewGroup.LayoutParams(web.width, web.height)); web.setBackgroundColor(Color.TRANSPARENT)
        }
        host?.x = web.x; host?.y = web.y
        host?.layoutParams = host?.layoutParams?.apply { width = web.width; height = web.height }
        val live = mutableSetOf<String>()
        for (index in 0 until frames.length()) {
            val frame = frames.getJSONObject(index); val id = frame.getString("track"); live += id
            val track = checkNotNull(available[id]); val previous = renderers[id]
            val view = if (previous?.first === track) previous.second else {
                previous?.let { it.first.removeRenderer(it.second); it.second.release(); host?.removeView(it.second) }
                TextureViewRenderer(web.context).also { current.initVideoRenderer(it); track.addRenderer(it); host?.addView(it); renderers[id] = track to it }
            }
            val scale = web.width / frame.getDouble("viewport_width")
            view.layoutParams = FrameLayout.LayoutParams((frame.getDouble("width") * scale).toInt(), (frame.getDouble("height") * scale).toInt()).apply {
                leftMargin = (frame.getDouble("x") * scale).toInt(); topMargin = (frame.getDouble("y") * scale).toInt()
            }
            view.setMirror(frame.optBoolean("mirror")); view.setScalingType(if (frame.optBoolean("fit")) RendererCommon.ScalingType.SCALE_ASPECT_FIT else RendererCommon.ScalingType.SCALE_ASPECT_FILL)
            view.bringToFront()
        }
        for (id in renderers.keys.toList()) if (id !in live) renderers.remove(id)?.let { it.first.removeRenderer(it.second); it.second.release(); host?.removeView(it.second) }
    }
    private fun clearRenderers() {
        renderers.values.forEach { (track, view) -> track.removeRenderer(view); view.release() }; renderers.clear()
        if (host != null) { (host?.parent as? ViewGroup)?.removeView(host); host = null; webView?.background = oldBackground; oldBackground = null }
    }
    private fun fail(reason: String) { failure = reason; room?.setMicrophoneMute(true); room?.setSpeakerMute(true); closeRoom() }
    private fun closeRoom() {
        clearRenderers(); eventJob?.cancel(); eventJob = null
        room?.setMicrophoneMute(true); room?.setSpeakerMute(true); room?.release(); room = null
        provider?.rtcKeyProvider?.dispose(); provider = null
        revision += 1
    }
    fun stop() { if (stopped) return; stopped = true; closeRoom(); jobs.cancel() }
}
