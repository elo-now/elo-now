package now.elo.push

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import app.tauri.plugin.JSObject
import org.json.JSONArray
import org.json.JSONObject
import org.webrtc.RendererCommon
import org.webrtc.SurfaceViewRenderer
import org.webrtc.VideoTrack
import java.util.UUID
import java.util.concurrent.Executors

/** One native media owner; WebView destruction detaches pixels, not an authorized call. */
@android.annotation.SuppressLint("StaticFieldLeak") // Renderers are released by attach(null) on WebView destruction; the peer holds only applicationContext.
internal object NativeMedia {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { runnable -> Thread(runnable, "elo-native-media") }
    @Volatile private var generation = 0L
    @Volatile private var currentId: String? = null
    private val systemMute = SystemMuteState()
    @Volatile private var peer: NativePeer? = null // Mutated on the media worker; cancellation only mutes from main.
    private var group: NativeGroup? = null
    private var webView: WebView? = null
    private var host: FrameLayout? = null
    private var oldBackground: Drawable? = null
    private var cameraEnabled = false
    private val renderers = mutableMapOf<String, Pair<VideoTrack, SurfaceViewRenderer>>()

    fun attach(web: WebView?) { checkMain(); clearRenderers(); webView = web; group?.attach(web) }
    fun foreground(activity: Activity) = !activity.isFinishing && !activity.isDestroyed &&
        (activity as? LifecycleOwner)?.lifecycle?.currentState?.isAtLeast(Lifecycle.State.RESUMED) == true
    fun granted(activity: Activity, video: Boolean) = ContextCompat.checkSelfPermission(activity, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED &&
        (!video || ContextCompat.checkSelfPermission(activity, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    fun stop(id: String? = null) {
        checkMain()
        if (id != null && currentId != id) { systemMute.end(id); return }
        currentId = null; generation += 1; cameraEnabled = false
        peer?.cancel()
        systemMute.end(id)
        group?.stop(); group = null
        clearRenderers()
        worker.execute { peer?.stop(); peer = null }
    }
    fun telecomMute(id: String): Long? {
        if (currentId != null && currentId != id) return null
        // Both mute and unmute requests close the local gate. Only the matching
        // signed acknowledgement can release it; driver updates cannot.
        return systemMute.request(id) {
            group?.muteMicrophone(true)
            peer?.silenceMicrophone()
        }
    }

    fun command(activity: Activity, request: JSONObject, completed: (JSObject) -> Unit) {
        checkMain()
        try {
            val op = request.getString("op")
            if (op == "shutdown") { stop(); completed(JSObject()); return }
            val id = request.getString("id")
            require(UUID.fromString(id).toString() == id)
            when (op) {
                "system_call_start" -> { OutgoingCalls.start(activity, request, completed); return }
                "system_call_connected" -> { OutgoingCalls.connected(id); completed(JSObject()); return }
                "system_call_end" -> { OutgoingCalls.end(id); completed(JSObject()); return }
            }
            if (op == "health") { completed(JSObject().put("live", currentId == id)); return }
            if (op in listOf("end_call", "stop")) { stop(id); completed(JSObject()); return }
            if (op == "start" || op == "group_start") {
                check(currentId == null) { "unavailable" }
                check(granted(activity, false)) { "NotAllowedError" }
                val incoming = IncomingCalls.authorizedMedia(id)
                val outgoing = OutgoingCalls.authorizedMedia(id)
                check(IncomingCalls.active() == null || incoming || outgoing) { "NotAllowedError" }
                check(foreground(activity) || incoming || outgoing) { "NotAllowedError" }
                if (incoming) IncomingCallService.authorizeCapture(activity, id, false)
                if (op == "start") require(request.getJSONArray("ice_servers").length() <= 16)
                currentId = id; generation += 1
            } else check(currentId == id) { "ended" }
            if (op == "update") {
                val video = request.getJSONObject("state").optBoolean("video_published")
                check(granted(activity, video)) { "NotAllowedError" }
                if (video && !cameraEnabled) check(foreground(activity)) { "NotAllowedError" }
                if (IncomingCalls.authorizedMedia(id)) IncomingCallService.authorizeCapture(activity, id, video)
                if (video != cameraEnabled) clearRenderers()
                cameraEnabled = video
            }
            if (op == "reset") clearRenderers()
            val token = generation
            val systemMuted = OutgoingCalls.muted(id) || IncomingCalls.muted(id)
            val approvedMuteRevision = request.optLong("system_mute_revision", -1)
            if (op == "group_start") group = NativeGroup(id, activity.applicationContext) { currentId == id && generation == token }.also {
                it.attach(webView)
                it.muteMicrophone(systemMuted || systemMute.blocked(id))
            }
            group?.let { active ->
                if (op == "update") systemMute.applyUpdate(id, approvedMuteRevision) { active.muteMicrophone(it) }
                active.command(request) { result ->
                    if (op == "update" && !result.has("error") && currentId == id && generation == token)
                        systemMute.applyUpdate(id, approvedMuteRevision) { active.muteMicrophone(it) }
                    completed(result)
                }
                return
            }
            worker.execute {
                try {
                    check(currentId == id && generation == token) { "ended" }
                    if (op == "start") {
                        synchronized(systemMute) {
                            peer = NativePeer(id, activity.applicationContext, request.getJSONArray("ice_servers"),
                                { work -> worker.execute(work) }, { currentId == id && generation == token }).also { it.muteMicrophone(systemMuted || systemMute.blocked(id)) }
                        }
                    }
                    val active = checkNotNull(peer?.takeIf { it.id == id }) { "ended" }
                    val result = when (op) {
                        "start" -> JSObject()
                        "reset" -> { active.reset(request.getJSONArray("ice_servers")); JSObject() }
                        "poll" -> active.poll(true)
                        "snapshot" -> active.poll(false)
                        "offer" -> { active.offer(request.optBoolean("restart")); JSObject() }
                        "signal" -> { active.signal(request.getJSONObject("signal")); JSObject() }
                        "update" -> {
                            systemMute.applyUpdate(id, approvedMuteRevision) { active.muteMicrophone(it) }
                            active.update(request.getJSONObject("state"), request.optBoolean("speaker_muted"))
                            systemMute.applyUpdate(id, approvedMuteRevision) { active.muteMicrophone(it) }
                            JSObject()
                        }
                        "speaker" -> { active.muteSpeaker(request.optBoolean("muted")); JSObject() }
                        "render" -> {
                            val frames = request.getJSONArray("frames")
                            require(frames.length() <= 4)
                            val tracks = (0 until frames.length()).associate { index ->
                                val frame = frames.getJSONObject(index)
                                val track = frame.getString("track")
                                track to checkNotNull(active.videoTrack(track)) { "unavailable" }
                            }
                            main.post {
                                try {
                                    check(currentId == id && generation == token) { "ended" }
                                    render(frames, tracks, active)
                                    completed(JSObject())
                                } catch (error: Exception) { completed(failure(error)) }
                            }
                            return@execute
                        }
                        else -> error("invalid")
                    }
                    main.post { completed(if (currentId == id && generation == token) result else JSObject().put("error", "ended")) }
                } catch (error: Exception) {
                    if (op in listOf("start", "reset", "signal", "offer", "poll", "snapshot")) main.post { if (currentId == id && generation == token) stop(id) }
                    main.post { completed(failure(error)) }
                }
            }
        } catch (error: Exception) { completed(failure(error)) }
    }
    private fun failure(error: Exception) = JSObject().put("error", when (error.message) { "NotAllowedError" -> "NotAllowedError"; "ended" -> "ended"; else -> "unavailable" })
    private fun render(frames: JSONArray, tracks: Map<String, VideoTrack>, peer: NativePeer) {
        checkMain()
        if (frames.length() == 0) { clearRenderers(); return }
        val web = checkNotNull(webView) { "unavailable" }
        val parent = web.parent as? ViewGroup ?: error("unavailable")
        // Validate the whole frame set before mutating any native view.
        for (index in 0 until frames.length()) {
            val frame = frames.getJSONObject(index)
            val values = listOf("x", "y", "width", "height", "viewport_width").map { frame.getDouble(it) }
            require(values.all { it.isFinite() } && values[4] > 0 && values[2] in 0.0..4096.0 && values[3] in 0.0..4096.0 &&
                kotlin.math.abs(values[0]) <= 4096 && kotlin.math.abs(values[1]) <= 4096)
        }
        if (host == null) {
            oldBackground = web.background
            host = FrameLayout(web.context).apply { isClickable = false; importantForAccessibility = android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS }
            parent.addView(host, parent.indexOfChild(web), ViewGroup.LayoutParams(web.width, web.height))
            web.setBackgroundColor(Color.TRANSPARENT)
        }
        host?.x = web.x; host?.y = web.y
        host?.layoutParams = host?.layoutParams?.apply { width = web.width; height = web.height }
        val live = mutableSetOf<String>()
        for (index in 0 until frames.length()) {
            val frame = frames.getJSONObject(index)
            val id = frame.getString("track")
            live += id
            val track = checkNotNull(tracks[id])
            val previous = renderers[id]
            val renderer = if (previous?.first === track) previous.second else {
                previous?.let { it.first.removeSink(it.second); it.second.release(); host?.removeView(it.second) }
                SurfaceViewRenderer(web.context).also {
                    it.init(peer.egl.eglBaseContext, null); it.setEnableHardwareScaler(true)
                    it.isClickable = false; track.addSink(it); host?.addView(it)
                    renderers[id] = track to it
                }
            }
            val scale = web.width / frame.getDouble("viewport_width")
            renderer.layoutParams = FrameLayout.LayoutParams((frame.getDouble("width") * scale).toInt(), (frame.getDouble("height") * scale).toInt()).apply {
                leftMargin = (frame.getDouble("x") * scale).toInt(); topMargin = (frame.getDouble("y") * scale).toInt()
            }
            renderer.setMirror(frame.optBoolean("mirror"))
            renderer.setScalingType(if (frame.optBoolean("fit")) RendererCommon.ScalingType.SCALE_ASPECT_FIT else RendererCommon.ScalingType.SCALE_ASPECT_FILL)
            renderer.bringToFront()
        }
        for (id in renderers.keys.toList()) if (id !in live) renderers.remove(id)?.let { it.first.removeSink(it.second); it.second.release(); host?.removeView(it.second) }
    }
    private fun clearRenderers() {
        for ((track, view) in renderers.values) { track.removeSink(view); view.release() }
        renderers.clear()
        if (host != null) { (host?.parent as? ViewGroup)?.removeView(host); host = null; webView?.background = oldBackground; oldBackground = null }
    }
    private fun checkMain() { check(Looper.myLooper() == Looper.getMainLooper()) }
}
