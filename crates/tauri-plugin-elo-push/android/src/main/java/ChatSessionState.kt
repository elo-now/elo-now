package now.elo.push

/** Process-only authorization: a delayed service intent cannot revive a left session. */
internal class ChatSessionState {
    data class Session(val id: String, val camera: Boolean, val revision: Long)

    private var revision = 0L
    private var current: Session? = null

    @Synchronized
    fun begin(id: String, camera: Boolean, foreground: Boolean, microphoneAllowed: Boolean, cameraAllowed: Boolean): Session {
        require(id.matches(Regex("[a-f0-9]{32}"))) { "Invalid chat session." }
        check(foreground) { "Open the app to join a chat session." }
        check(microphoneAllowed && (!camera || cameraAllowed)) { "Allow microphone or camera access before joining." }
        check(current == null || current?.id == id) { "Leave the current chat session first." }
        return Session(id, camera, ++revision).also { current = it }
    }

    @Synchronized
    fun matching(action: String?, id: String?, revision: Long): Session? =
        current?.takeIf { action == ACTION && it.id == id && it.revision == revision }

    @Synchronized
    fun active(): Session? = current

    @Synchronized
    fun end(id: String? = null, expectedRevision: Long? = null): Boolean {
        if (id != null && current?.id != id) return false
        if (expectedRevision != null && current?.revision != expectedRevision) return false
        current = null
        ++revision
        return true
    }

    companion object {
        const val ACTION = "now.elo.push.UPDATE_CHAT_SESSION"
        const val SESSION_ID = "session_id"
        const val REVISION = "session_revision"
    }
}
