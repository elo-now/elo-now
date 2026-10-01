package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class ChatSessionStateTest {
    private val id = "ab".repeat(16)
    private val other = "cd".repeat(16)

    @Test fun aPushOrBackgroundAppCannotAuthorizeCapture() {
        val state = ChatSessionState()
        assertThrows(IllegalStateException::class.java) {
            state.begin(id, false, foreground = false, microphoneAllowed = true, cameraAllowed = true)
        }
        assertNull(state.active())
        assertNull(state.matching(ChatSessionState.ACTION, id, 1))
        assertNull(state.matching("android.intent.action.BOOT_COMPLETED", id, 1))
        assertNull(state.matching(null, id, 1))
    }

    @Test fun microphonePermissionIsRequiredButAudioDoesNotRequireCameraPermission() {
        val state = ChatSessionState()
        assertThrows(IllegalStateException::class.java) {
            state.begin(id, false, foreground = true, microphoneAllowed = false, cameraAllowed = true)
        }
        assertNull(state.active())
        val session = state.begin(id, false, foreground = true, microphoneAllowed = true, cameraAllowed = false)
        assertFalse(session.camera)
        assertEquals(session, state.matching(ChatSessionState.ACTION, id, session.revision))
    }

    @Test fun addingVideoRequiresForegroundAndItsOwnGrantedPermission() {
        val state = ChatSessionState()
        val audio = state.begin(id, false, true, true, false)
        assertThrows(IllegalStateException::class.java) { state.begin(id, true, true, true, false) }
        assertThrows(IllegalStateException::class.java) { state.begin(id, true, false, true, true) }
        assertEquals(audio, state.active())
        val video = state.begin(id, true, true, true, true)
        assertTrue(video.camera)
        assertNull(state.matching(ChatSessionState.ACTION, id, audio.revision))
        assertEquals(video, state.matching(ChatSessionState.ACTION, id, video.revision))
    }

    @Test fun leavingInvalidatesQueuedServiceStartsAndUpdates() {
        val state = ChatSessionState()
        val first = state.begin(id, false, true, true, false)
        assertTrue(state.end(id))
        assertNull(state.matching(ChatSessionState.ACTION, id, first.revision))
        val rejoined = state.begin(id, false, true, true, false)
        assertNotEquals(first.revision, rejoined.revision)
        assertNull(state.matching(ChatSessionState.ACTION, id, first.revision))
        assertFalse(state.end(id, first.revision))
        assertEquals(rejoined, state.active())
    }

    @Test fun anotherSessionCannotReplaceOrStopTheCurrentSession() {
        val state = ChatSessionState()
        val session = state.begin(id, false, true, true, false)
        assertThrows(IllegalStateException::class.java) { state.begin(other, false, true, true, false) }
        assertFalse(state.end(other))
        assertNull(state.matching(ChatSessionState.ACTION, other, session.revision))
        assertEquals(session, state.active())
        assertTrue(state.end())
        assertNull(state.active())
    }

    @Test fun processRestartAndMalformedIdsCannotRestoreAnActiveSession() {
        val session = ChatSessionState().begin(id, false, true, true, false)
        val restarted = ChatSessionState()
        assertNull(restarted.matching(ChatSessionState.ACTION, id, session.revision))
        for (invalid in listOf("", "../session", "AB".repeat(16), "ab".repeat(17))) {
            assertThrows(IllegalArgumentException::class.java) { restarted.begin(invalid, false, true, true, false) }
        }
        assertNull(restarted.active())
    }
}
