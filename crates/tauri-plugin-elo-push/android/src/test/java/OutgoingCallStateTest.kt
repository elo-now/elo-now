package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class OutgoingCallStateTest {
    private val first = OutgoingCallState.Lease("11111111-1111-4111-8111-111111111111", "ab".repeat(16), "22222222-2222-4222-8222-222222222222")
    private val second = OutgoingCallState.Lease("33333333-3333-4333-8333-333333333333", first.callId, "44444444-4444-4444-8444-444444444444")

    @Test fun registrationAndDuplicateStartDoNotClaimConnectedMedia() {
        val state = OutgoingCallState()
        assertTrue(state.begin(first))
        assertFalse(state.isConnected(first))
        assertFalse(state.begin(first))
        assertFalse(state.isConnected(first))
        assertTrue(state.connected(first))
        assertTrue(state.isConnected(first))
    }

    @Test fun oldTelecomCallbacksCannotConnectMuteOrEndAReplacementOfTheSameCall() {
        val state = OutgoingCallState()
        state.begin(first)
        state.connected(first)
        assertTrue(state.end(first))
        state.begin(second)
        assertFalse(state.owns(first))
        assertFalse(state.connected(first))
        assertFalse(state.end(first))
        assertEquals(second, state.active())
        assertFalse(state.isConnected(second))
        assertTrue(state.connected(second))
    }

    @Test fun anotherCallRequiresEndingTheCurrentOwnerFirst() {
        val state = OutgoingCallState()
        state.begin(first)
        assertThrows(IllegalStateException::class.java) { state.begin(second) }
        assertEquals(first, state.active())
        assertFalse(state.end(first.copy(activation = second.activation)))
        assertEquals(first, state.active())
    }

    @Test fun restartingTheProcessCannotRestoreAuthorityFromAnOldTelecomIntent() {
        OutgoingCallState().begin(first)
        val restarted = OutgoingCallState()
        assertFalse(restarted.owns(first))
        assertFalse(restarted.connected(first))
        assertFalse(restarted.end(first))
        assertNull(restarted.active())
    }

    @Test fun malformedIdentifiersNeverCreateAnOwner() {
        val state = OutgoingCallState()
        for (invalid in listOf(first.copy(mediaId = "1-1-1-1-1"), first.copy(activation = "bad"), first.copy(callId = "AB".repeat(16)))) {
            assertThrows(IllegalArgumentException::class.java) { state.begin(invalid) }
            assertNull(state.active())
        }
    }
}
