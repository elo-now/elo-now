package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class SystemMuteStateTest {
    @Test fun ordinaryDriverUpdateCannotApproveSystemUnmuteEvenAfterAcknowledgement() {
        val gate = SystemMuteState()
        var capturedMuted = false
        val revision = gate.request("capture") { capturedMuted = true }
        assertTrue(gate.blocked("capture"))
        assertFalse(gate.applyUpdate("capture", -1) { capturedMuted = it })
        assertTrue(capturedMuted)
        assertTrue(gate.applyUpdate("capture", revision) { capturedMuted = it })
        assertFalse(capturedMuted)
        assertFalse(gate.blocked("capture"))
        assertFalse(gate.applyUpdate("capture", -1) { capturedMuted = it })
        assertTrue(capturedMuted)
        assertTrue(gate.applyUpdate("capture", revision) { capturedMuted = it })
        assertFalse(capturedMuted)
    }
    @Test fun lateSignedUnmuteCannotUndoANewerSystemMute() {
        val gate = SystemMuteState()
        val older = gate.request("capture") {}
        val latest = gate.request("capture") {}
        assertFalse(gate.applyUpdate("capture", older) { assertTrue(it) })
        assertTrue(gate.blocked("capture"))
        assertTrue(gate.applyUpdate("capture", latest) { assertFalse(it) })
    }
    @Test fun oldEndAndOldRevisionCannotChangeAReplacementCapture() {
        val gate = SystemMuteState()
        val older = gate.request("old") {}
        gate.end("old")
        val latest = gate.request("new") {}
        gate.end("old")
        assertTrue(gate.blocked("new"))
        assertFalse(gate.applyUpdate("old", older) { assertTrue(it) })
        assertFalse(gate.applyUpdate("new", older) { assertTrue(it) })
        assertTrue(gate.applyUpdate("new", latest) { assertFalse(it) })
    }
}
