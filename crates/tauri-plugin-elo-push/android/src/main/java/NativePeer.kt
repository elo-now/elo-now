package now.elo.push

import android.content.Context
import app.tauri.plugin.JSObject
import org.json.JSONArray
import org.json.JSONObject
import org.webrtc.*
import org.webrtc.audio.JavaAudioDeviceModule
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** SDP and ICE arrive only through Rust's verified, recipient-encrypted signaling. */
internal class NativePeer(
    val id: String,
    private val context: Context,
    private val servers: JSONArray,
    private val dispatch: (() -> Unit) -> Unit,
    private val authorized: () -> Boolean,
) {
    val egl: EglBase = EglBase.create()
    private val audioDevice = run {
        PeerConnectionFactory.initialize(PeerConnectionFactory.InitializationOptions.builder(context).createInitializationOptions())
        JavaAudioDeviceModule.builder(context).createAudioDeviceModule()
    }
    private val factory: PeerConnectionFactory
    private var pc: PeerConnection? = null
    private var audioSource: AudioSource? = null
    private var audio: AudioTrack? = null
    private var cameraSource: VideoSource? = null
    private var camera: VideoTrack? = null
    private var capturer: CameraVideoCapturer? = null
    private var texture: SurfaceTextureHelper? = null
    private var channels = emptyList<RtpTransceiver>()
    private val candidates = mutableListOf<IceCandidate>()
    private val signals = mutableListOf<JSONObject>()
    private var acceptedOffer: String? = null
    private var acceptedAnswer: String? = null
    private var epoch = 0L
    @Volatile private var stopped = false
    @Volatile private var cancelled = false
    private var connection = "new"
    private var revision = 0
    private var speakerMuted = false
    @Volatile private var systemMuted = false
    private val microphoneLock = Any()
    private var media = JSONObject()

    init {
        factory = PeerConnectionFactory.builder().setAudioDeviceModule(audioDevice)
            .setVideoEncoderFactory(DefaultVideoEncoderFactory(egl.eglBaseContext, true, true))
            .setVideoDecoderFactory(DefaultVideoDecoderFactory(egl.eglBaseContext)).createPeerConnectionFactory()
        try {
            pc = create(servers)
            audioSource = factory.createAudioSource(MediaConstraints())
            audio = factory.createAudioTrack("microphone", audioSource).apply { setEnabled(false) }
            pc?.setAudioRecording(false)
        } catch (error: Exception) { stop(); throw error }
    }

    private fun create(servers: JSONArray): PeerConnection {
        require(servers.length() <= 16)
        val ice = (0 until servers.length()).map { index ->
            val value = servers.getJSONObject(index)
            val raw = value.get("urls")
            val urls = if (raw is JSONArray) (0 until raw.length()).map { raw.getString(it) } else listOf(raw as String)
            require(urls.isNotEmpty() && urls.size <= 8 && urls.all { url -> url.length <= 2048 && listOf("stun:", "stuns:", "turn:", "turns:").any(url::startsWith) })
            PeerConnection.IceServer.builder(urls).setUsername(value.optString("username")).setPassword(value.optString("credential")).createIceServer()
        }
        val config = PeerConnection.RTCConfiguration(ice).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
            continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
        }
        val generation = epoch
        fun current(action: () -> Unit) = dispatch { if (!stopped && generation == epoch && authorized()) action() }
        return checkNotNull(factory.createPeerConnection(config, object : PeerConnection.Observer {
            override fun onSignalingChange(state: PeerConnection.SignalingState) {}
            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {}
            override fun onIceConnectionReceivingChange(receiving: Boolean) {}
            override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {}
            override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {}
            override fun onAddStream(stream: MediaStream) {}
            override fun onRemoveStream(stream: MediaStream) {}
            override fun onDataChannel(channel: DataChannel) { channel.close() }
            override fun onRenegotiationNeeded() {}
            override fun onConnectionChange(state: PeerConnection.PeerConnectionState) = current { connection = state.name.lowercase() }
            override fun onIceCandidate(candidate: IceCandidate) = current {
                emit(JSONObject().put("type", "ice").put("candidate", candidate.sdp)
                    .put("sdp_mid", candidate.sdpMid ?: JSONObject.NULL).put("sdp_mline_index", candidate.sdpMLineIndex))
            }
            override fun onTrack(transceiver: RtpTransceiver) = current { revision += 1 }
        }))
    }
    private fun live(): PeerConnection {
        check(!stopped && !cancelled && authorized()) { "ended" }
        return checkNotNull(pc) { "ended" }
    }
    private fun emit(signal: JSONObject) {
        if (signals.size >= 256) { cancel(); connection = "failed"; return }
        signals += signal
    }
    private fun sdp(start: (SdpObserver) -> Unit): SessionDescription? {
        val latch = CountDownLatch(1)
        var result: SessionDescription? = null
        var failure: String? = null
        start(object : SdpObserver {
            override fun onCreateSuccess(value: SessionDescription) { result = value; latch.countDown() }
            override fun onSetSuccess() { latch.countDown() }
            override fun onCreateFailure(error: String) { failure = error; latch.countDown() }
            override fun onSetFailure(error: String) { failure = error; latch.countDown() }
        })
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (!latch.await(50, TimeUnit.MILLISECONDS)) {
            if (cancelled || !authorized()) { cancel(); error("ended") }
            if (System.nanoTime() >= deadline) { cancel(); error("unavailable") }
        }
        if (failure != null) { cancel(); error("unavailable") }
        live()
        return result
    }
    fun reset(servers: JSONArray) {
        live(); epoch += 1
        channels = emptyList(); candidates.clear(); signals.clear()
        acceptedOffer = null; acceptedAnswer = null
        pc?.dispose(); pc = null
        try { pc = create(servers); pc?.setAudioRecording(!media.optBoolean("audio_muted", true) && !systemMuted) }
        catch (error: Exception) { stop(); throw error }
        connection = "new"; revision += 1
    }
    fun offer(restart: Boolean) {
        val current = live()
        if (channels.isEmpty()) {
            val settings = RtpTransceiver.RtpTransceiverInit(RtpTransceiver.RtpTransceiverDirection.SEND_RECV)
            channels = listOf(MediaStreamTrack.MediaType.MEDIA_TYPE_AUDIO, MediaStreamTrack.MediaType.MEDIA_TYPE_VIDEO, MediaStreamTrack.MediaType.MEDIA_TYPE_VIDEO)
                .map { checkNotNull(current.addTransceiver(it, settings)) }
            applyTracks()
        }
        if (current.signalingState() == PeerConnection.SignalingState.STABLE) {
            val constraints = MediaConstraints().apply { if (restart) mandatory.add(MediaConstraints.KeyValuePair("IceRestart", "true")) }
            val description = checkNotNull(sdp { current.createOffer(it, constraints) })
            sdp { current.setLocalDescription(it, description) }
        }
        if (current.signalingState() == PeerConnection.SignalingState.HAVE_LOCAL_OFFER) current.localDescription?.let {
            emit(JSONObject().put("type", "offer").put("sdp", it.description))
        }
    }
    fun signal(value: JSONObject) {
        val current = live()
        when (value.getString("type")) {
            "request_offer" -> offer(true)
            "ice" -> {
                val raw = value.getString("candidate")
                val line = value.getInt("sdp_mline_index")
                require(raw.length <= 8192 && line in 0..2)
                val candidate = IceCandidate(value.optString("sdp_mid").takeIf { !value.isNull("sdp_mid") }, line, raw)
                if (current.remoteDescription != null) check(current.addIceCandidate(candidate))
                else { require(candidates.size < 128); candidates += candidate }
            }
            "offer", "answer" -> {
                val answering = value.getString("type") == "answer"
                val raw = value.getString("sdp")
                require(raw.toByteArray(Charsets.UTF_8).size <= 131072)
                if (answering && current.signalingState() == PeerConnection.SignalingState.STABLE) return
                if (raw == (if (answering) acceptedAnswer else acceptedOffer)) {
                    if (answering) return
                    if (current.signalingState() == PeerConnection.SignalingState.STABLE && current.localDescription?.type == SessionDescription.Type.ANSWER) {
                        emit(JSONObject().put("type", "answer").put("sdp", current.localDescription.description)); return
                    }
                }
                sdp { current.setRemoteDescription(it, SessionDescription(if (answering) SessionDescription.Type.ANSWER else SessionDescription.Type.OFFER, raw)) }
                if (answering) acceptedAnswer = raw else acceptedOffer = raw
                candidates.forEach { live(); check(current.addIceCandidate(it)) }; candidates.clear()
                if (!answering) {
                    if (channels.isEmpty()) {
                        channels = current.transceivers.filter { it.mid != null }
                        require(channels.size == 3 && channels.map { it.mediaType } == listOf(MediaStreamTrack.MediaType.MEDIA_TYPE_AUDIO, MediaStreamTrack.MediaType.MEDIA_TYPE_VIDEO, MediaStreamTrack.MediaType.MEDIA_TYPE_VIDEO))
                        channels.forEach { check(it.setDirection(RtpTransceiver.RtpTransceiverDirection.SEND_RECV)) }
                    }
                    applyTracks()
                    val answer = checkNotNull(sdp { current.createAnswer(it, MediaConstraints()) })
                    sdp { current.setLocalDescription(it, answer) }
                    emit(JSONObject().put("type", "answer").put("sdp", current.localDescription.description))
                }
                revision += 1
            }
            else -> error("invalid")
        }
    }
    fun update(next: JSONObject, speakerMuted: Boolean) {
        live(); require(!next.optBoolean("screen_published"))
        if (next.optBoolean("video_published") && camera == null) {
            val source = factory.createVideoSource(false)
            val enumerator = Camera2Enumerator(context)
            val device = enumerator.deviceNames.firstOrNull(enumerator::isFrontFacing) ?: enumerator.deviceNames.firstOrNull() ?: error("unavailable")
            val capture = checkNotNull(enumerator.createCapturer(device, null))
            val helper = SurfaceTextureHelper.create("elo-camera", egl.eglBaseContext)
            try {
                capture.initialize(helper, context, source.capturerObserver)
                live(); capture.startCapture(1280, 720, 30)
                cameraSource = source; capturer = capture; texture = helper
                camera = factory.createVideoTrack("camera", source); revision += 1
            } catch (error: Exception) { capture.dispose(); helper.dispose(); source.dispose(); throw error }
        } else if (!next.optBoolean("video_published") && camera != null) {
            channels.getOrNull(1)?.sender?.setTrack(null, false)
            stopCamera(); revision += 1
        }
        live()
        media = JSONObject(next.toString())
        applyMicrophone()
        muteSpeaker(speakerMuted)
        applyTracks()
    }
    private fun applyTracks() {
        live()
        if (channels.size != 3) return
        check(channels[0].sender.setTrack(audio, false))
        check(channels[1].sender.setTrack(camera, false))
        check(channels[2].sender.setTrack(null, false))
        channels[0].receiver.track()?.setEnabled(!speakerMuted)
    }
    fun muteSpeaker(muted: Boolean) { speakerMuted = muted; audioDevice.setSpeakerMute(muted); channels.firstOrNull()?.receiver?.track()?.setEnabled(!muted) }
    fun silenceMicrophone() = synchronized(microphoneLock) {
        if (!stopped) { systemMuted = true; audioDevice.setMicrophoneMute(true) }
    }
    fun muteMicrophone(muted: Boolean) = synchronized(microphoneLock) { systemMuted = muted; applyMicrophone() }
    private fun applyMicrophone() = synchronized(microphoneLock) {
        val muted = stopped || cancelled || systemMuted || media.optBoolean("audio_muted", true)
        audioDevice.setMicrophoneMute(muted); audio?.setEnabled(!muted); pc?.setAudioRecording(!muted)
    }
    fun videoTrack(id: String): VideoTrack? = when (id) {
        "local-camera" -> camera
        "remote-camera" -> channels.getOrNull(1)?.receiver?.track() as? VideoTrack
        "remote-screen" -> channels.getOrNull(2)?.receiver?.track() as? VideoTrack
        else -> null
    }
    fun poll(drain: Boolean): JSObject {
        live()
        val pending = if (drain) signals.toList() else emptyList()
        if (drain) signals.clear()
        val tracks = JSONArray()
        if (camera != null) tracks.put(JSONObject().put("id", "local-camera").put("source", "camera").put("local", true))
        for ((id, source) in listOf("remote-camera" to "camera", "remote-screen" to "screen")) {
            if (videoTrack(id) != null) tracks.put(JSONObject().put("id", id).put("source", source).put("local", false))
        }
        return JSObject().put("connection", connection).put("revision", revision).put("signals", JSONArray(pending)).put("tracks", tracks)
            .put("media", JSONObject(media.toString()).put("audio_muted", systemMuted || media.optBoolean("audio_muted", true)))
    }
    private fun stopCamera() {
        runCatching { capturer?.stopCapture() }; capturer?.dispose(); capturer = null
        texture?.dispose(); texture = null; camera?.dispose(); camera = null; cameraSource?.dispose(); cameraSource = null
    }
    /** Mute immediately even while the serialized worker awaits an SDP callback. */
    fun cancel() = synchronized(microphoneLock) {
        if (!stopped) {
            cancelled = true
            audioDevice.setMicrophoneMute(true)
            audioDevice.setSpeakerMute(true)
        }
    }
    fun stop() {
        if (stopped) return
        stopped = true; cancelled = true; epoch += 1
        audio?.setEnabled(false); pc?.setAudioRecording(false)
        pc?.dispose(); pc = null; channels = emptyList()
        stopCamera(); audio?.dispose(); audio = null; audioSource?.dispose(); audioSource = null
        audioDevice.release(); factory.dispose(); egl.release()
        signals.clear(); candidates.clear(); connection = "closed"; revision += 1
    }
}
