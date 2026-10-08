package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class ForegroundRingtoneStateTest {
    @Test fun cancellationBeforeStartAndLifecycleStopCannotBeUndone() {
        val state = ForegroundRingtoneState()
        state.update("one", 2, false, 0, 0)
        assertFalse(state.update("one", 1, true, 4000, 0))
        assertFalse(state.live(0))
        assertTrue(state.update("two", 1, true, 4000, 0))
        state.stop()
        assertFalse(state.update("two", 2, true, 4500, 500))
        assertFalse(state.live(500))
    }

    @Test fun renewalIgnoresOldRevisionsAndAnExpiredTokenCannotRestart() {
        val state = ForegroundRingtoneState()
        assertTrue(state.update("one", 1, true, 4000, 0))
        assertTrue(state.update("one", 2, true, 5500, 1500))
        assertFalse(state.update("one", 1, true, 4000, 1500))
        assertTrue(state.live(5000))
        assertFalse(state.live(5500))
        assertFalse(state.update("one", 3, true, 9500, 5500))
        assertFalse(state.live(5500))
    }

    @Test fun oldCancellationCannotStopAReplacementAndLeasesAreBounded() {
        val state = ForegroundRingtoneState()
        assertTrue(state.update("one", 1, true, 4000, 0))
        assertTrue(state.update("two", 1, true, 4000, 0))
        state.update("one", 2, false, 0, 0)
        assertEquals("two", state.token)
        assertFalse(state.update("unbounded", 1, true, 6000, 0))
        assertFalse(state.update("expired", 1, true, 100, 100))
        assertEquals("two", state.token)
    }

    @Test fun logoutEpochRejectsUnknownDelayedStartsAndOldShutdowns() {
        val state = ForegroundRingtoneState()
        assertTrue(state.admit(1))
        assertFalse(state.admit(0))
        assertTrue(state.update("new-profile", 1, true, 4000, 0))
        assertFalse(state.admit(0))
        assertEquals("new-profile", state.token)
        assertTrue(state.admit(2))
        assertFalse(state.live(0))
    }
}
