package now.elo.push

import android.content.Context
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import app.tauri.plugin.JSObject
import org.json.JSONArray
import org.json.JSONObject

/** One explicit session owns routing; microphone and remote mute remain separate. */
internal object ChatSessionAudio {
    private val handler = Handler(Looper.getMainLooper())
    private var sessionId: String? = null
    private var activation: String? = null
    private var manager: AudioManager? = null
    private var previousMode = AudioManager.MODE_NORMAL
    private var previousSpeaker = false
    private var selectedByUs = false
    private var initialDevices = emptySet<Int>()
    private var removeCommunicationListener: (() -> Unit)? = null
    private var changed: ((JSObject) -> Unit)? = null
    private var systemActions: ((JSObject) -> Unit)? = null
    private var telecomManaged = false

    fun telecomChanged() { changed?.invoke(JSObject()) }
    fun detach() { changed = null }

    fun owns(id: String, activation: String) = sessionId == id && this.activation == activation

    fun listen(id: String, activation: String, listener: ((JSObject) -> Unit)?) {
        if (owns(id, activation)) { changed = listener; systemActions = listener }
    }

    fun systemAction(id: String, activation: String, action: String, muted: Boolean? = null, systemMuteRevision: Long? = null) {
        if (!owns(id, activation)) return
        val value = JSObject().put("action", action)
        if (muted != null) value.put("muted", muted)
        if (systemMuteRevision != null) value.put("systemMuteRevision", systemMuteRevision)
        runCatching { systemActions?.invoke(value) }
    }

    fun adoptTelecom(id: String, activation: String) {
        if (!owns(id, activation) || telecomManaged) return
        val audio = manager ?: return
        runCatching { audio.unregisterAudioDeviceCallback(devicesChanged) }
        runCatching { removeCommunicationListener?.invoke() }
        removeCommunicationListener = null
        runCatching {
            if (Build.VERSION.SDK_INT >= 31) audio.clearCommunicationDevice()
            else if (selectedByUs) LegacyAudio.speaker(audio, previousSpeaker)
        }
        selectedByUs = false
        initialDevices = emptySet()
        telecomManaged = true
        telecomChanged()
    }

    private val devicesChanged = object : AudioDeviceCallback() {
        override fun onAudioDevicesAdded(devices: Array<out AudioDeviceInfo>) {
            val audio = manager ?: return
            if (devices.any { it.isSink && externalKind(it.type) != null && it.id !in initialDevices }) {
                // Connecting a headset cancels our built-in override. Selection
                // is never reapplied on camera updates or subsequent callbacks.
                runCatching {
                    if (Build.VERSION.SDK_INT >= 31) audio.clearCommunicationDevice()
                    else LegacyAudio.speaker(audio, false)
                    selectedByUs = false
                }
            }
            initialDevices = audio.getDevices(AudioManager.GET_DEVICES_OUTPUTS).map { it.id }.toSet()
            changed?.invoke(JSObject())
        }
        override fun onAudioDevicesRemoved(devices: Array<out AudioDeviceInfo>) {
            manager?.let { audio -> initialDevices = audio.getDevices(AudioManager.GET_DEVICES_OUTPUTS).map { it.id }.toSet() }
            changed?.invoke(JSObject())
        }
    }

    fun begin(context: Context, id: String, activation: String) {
        check(Looper.myLooper() == Looper.getMainLooper())
        check(sessionId == null || (sessionId == id && this.activation == activation))
        if (sessionId == id) return
        val audio = context.applicationContext.getSystemService(AudioManager::class.java)
        previousMode = audio.mode
        if (Build.VERSION.SDK_INT < 31) previousSpeaker = LegacyAudio.speaker(audio)
        manager = audio
        sessionId = id
        this.activation = activation
        telecomManaged = IncomingCalls.ownsTelecom(id) || OutgoingCalls.owns(id)
        // Telecom owns focus, device selection and communication mode for a
        // self-managed call. Independent AudioManager overrides fight its routes.
        if (telecomManaged) return
        initialDevices = audio.getDevices(AudioManager.GET_DEVICES_OUTPUTS).map { it.id }.toSet()
        try {
            audio.mode = AudioManager.MODE_IN_COMMUNICATION
            // Preserve the existing loudspeaker default, but only on the first
            // join and only while no external route is attached. Route errors
            // cannot prevent an otherwise valid chat session from starting.
            val externalAttached = audio.getDevices(AudioManager.GET_DEVICES_OUTPUTS)
                .any { it.isSink && externalKind(it.type) != null }
            if (!externalAttached) runCatching {
                if (Build.VERSION.SDK_INT >= 31) {
                    audio.availableCommunicationDevices.firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
                        ?.let { selectedByUs = audio.setCommunicationDevice(it) }
                } else {
                    LegacyAudio.speaker(audio, true)
                    selectedByUs = true
                }
            }
            audio.registerAudioDeviceCallback(devicesChanged, handler)
            if (Build.VERSION.SDK_INT >= 31) {
                val listener = AudioManager.OnCommunicationDeviceChangedListener { changed?.invoke(JSObject()) }
                audio.addOnCommunicationDeviceChangedListener(context.mainExecutor, listener)
                removeCommunicationListener = { audio.removeOnCommunicationDeviceChangedListener(listener) }
            }
        } catch (error: RuntimeException) {
            stop(id)
            throw error
        }
    }

    fun stop(id: String? = null) {
        if (id != null && sessionId != id) return
        val audio = manager ?: return
        sessionId = null
        activation = null
        changed = null
        systemActions = null
        if (telecomManaged) {
            telecomManaged = false
            manager = null
            return
        }
        runCatching { audio.unregisterAudioDeviceCallback(devicesChanged) }
        runCatching { removeCommunicationListener?.invoke() }
        removeCommunicationListener = null
        runCatching {
            if (Build.VERSION.SDK_INT >= 31) audio.clearCommunicationDevice()
            else if (selectedByUs) LegacyAudio.speaker(audio, previousSpeaker)
        }
        // Do not overwrite a different mode now owned by another audio activity.
        if (audio.mode == AudioManager.MODE_IN_COMMUNICATION) runCatching { audio.mode = previousMode }
        selectedByUs = false
        manager = null
        initialDevices = emptySet()
    }

    fun route(id: String, activation: String, outputId: String?): JSObject {
        check(Looper.myLooper() == Looper.getMainLooper())
        check(sessionId == id && this.activation == activation && ChatSessions.state.active()?.id == id)
        val audio = checkNotNull(manager)
        return if (Build.VERSION.SDK_INT >= 31) modernRoute(audio, outputId) else legacyRoute(audio, outputId)
    }

    @androidx.annotation.RequiresApi(31)
    private fun modernRoute(audio: AudioManager, outputId: String?): JSObject {
        val devices = audio.availableCommunicationDevices.filter { it.isSink }
        if (outputId != null) {
            if (outputId == "system") {
                audio.clearCommunicationDevice()
                selectedByUs = false
            } else {
                val device = devices.firstOrNull { deviceId(it) == outputId } ?: error("unavailable")
                check(audio.setCommunicationDevice(device)) { "unavailable" }
                selectedByUs = true
            }
        }
        val outputs = JSONArray()
        devices.forEach { outputs.put(output(it)) }
        outputs.put(JSObject().put("id", "system").put("kind", "system"))
        val actual = audio.communicationDevice
        val selected = actual?.let { device -> devices.firstOrNull { it.id == device.id }?.let(::deviceId) }
        return JSObject().put("selected", selected ?: JSONObject.NULL).put("outputs", outputs)
    }

    private fun legacyRoute(audio: AudioManager, outputId: String?): JSObject {
        val devices = audio.getDevices(AudioManager.GET_DEVICES_OUTPUTS).filter { it.isSink }
        // Old Android cannot choose a particular communication device. Preserve
        // the system's headset routing rather than selecting a fictitious one.
        val external = devices.firstOrNull { externalKind(it.type) == "headphones" }
            ?: devices.firstOrNull { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO && LegacyAudio.bluetooth(audio) }
        val hasReceiver = devices.any { it.type == AudioDeviceInfo.TYPE_BUILTIN_EARPIECE }
        if (outputId != null) {
            check(outputId == "system" || (outputId == "speaker" && (external == null || LegacyAudio.speaker(audio))) ||
                (outputId == "receiver" && external == null && hasReceiver)) { "unavailable" }
            LegacyAudio.speaker(audio, outputId == "speaker")
            selectedByUs = true
            changed?.invoke(JSObject())
        }
        val speakerActive = LegacyAudio.speaker(audio)
        val outputs = JSONArray()
        if (external == null) {
            if (hasReceiver) outputs.put(JSObject().put("id", "receiver").put("kind", "receiver"))
            outputs.put(JSObject().put("id", "speaker").put("kind", "speaker"))
        } else if (speakerActive) {
            outputs.put(JSObject().put("id", "speaker").put("kind", "speaker"))
        }
        outputs.put(JSObject().put("id", "system").put("kind", external?.let { externalKind(it.type) } ?: "system").also {
            if (external != null) it.put("name", external.productName.toString().take(120))
        })
        val selected = when {
            speakerActive -> "speaker"
            external != null -> "system"
            hasReceiver -> "receiver"
            else -> "system"
        }
        return JSObject().put("selected", selected).put("outputs", outputs)
    }

    private fun deviceId(device: AudioDeviceInfo) = "device:" + device.id
    private fun output(device: AudioDeviceInfo): JSObject {
        val kind = when (device.type) {
            AudioDeviceInfo.TYPE_BUILTIN_EARPIECE -> "receiver"
            AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, AudioDeviceInfo.TYPE_BUILTIN_SPEAKER_SAFE -> "speaker"
            else -> externalKind(device.type) ?: "system"
        }
        return JSObject().put("id", deviceId(device)).put("kind", kind).also {
            if (kind != "receiver" && kind != "speaker") it.put("name", device.productName.toString().take(120))
        }
    }
    private fun externalKind(type: Int): String? = when (type) {
        AudioDeviceInfo.TYPE_BLUETOOTH_SCO, AudioDeviceInfo.TYPE_BLUETOOTH_A2DP,
        AudioDeviceInfo.TYPE_BLE_HEADSET, AudioDeviceInfo.TYPE_BLE_SPEAKER, AudioDeviceInfo.TYPE_HEARING_AID -> "bluetooth"
        AudioDeviceInfo.TYPE_WIRED_HEADSET, AudioDeviceInfo.TYPE_WIRED_HEADPHONES,
        AudioDeviceInfo.TYPE_USB_HEADSET, AudioDeviceInfo.TYPE_USB_DEVICE -> "headphones"
        else -> null
    }
}

/** Android 8.1–11 has no setCommunicationDevice. Never used on API 31+. */
@Suppress("DEPRECATION")
private object LegacyAudio {
    fun speaker(audio: AudioManager) = audio.isSpeakerphoneOn
    fun speaker(audio: AudioManager, enabled: Boolean) { audio.isSpeakerphoneOn = enabled }
    fun bluetooth(audio: AudioManager) = audio.isBluetoothScoOn
}
