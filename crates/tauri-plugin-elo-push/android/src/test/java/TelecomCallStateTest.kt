package now.elo.push

import org.junit.Assert.*
import org.junit.Test
import now.elo.push.TelecomCallState.Command

class TelecomCallStateTest {
    @Test fun cancelledBeforeTelecomIsReadyNeverAnswersOrRingsAgain() {
        val state = TelecomCallState()
        state.connected = true
        state.ended = true
        assertNull(state.nextCommand())
        state.ready = true
        assertEquals(Command.DISCONNECT, state.nextCommand())
        assertNull(state.nextCommand())
    }

    @Test fun connectedBeforeTelecomIsReadyAnswersExactlyOnce() {
        val state = TelecomCallState()
        state.connected = true
        assertNull(state.nextCommand())
        state.ready = true
        assertEquals(Command.ANSWER, state.nextCommand())
        state.connected = true
        assertNull(state.nextCommand())
        state.ended = true
        assertEquals(Command.DISCONNECT, state.nextCommand())
        assertNull(state.nextCommand())
    }

    @Test fun answerFromSystemDoesNotSendAnotherAnswerToSystem() {
        val state = TelecomCallState()
        state.answeredBySystem = true
        state.connected = true
        state.ready = true
        assertNull(state.nextCommand())
        state.ended = true
        assertEquals(Command.DISCONNECT, state.nextCommand())
    }

    @Test fun systemDisconnectIsTerminalEvenIfMediaConnectsLate() {
        val state = TelecomCallState()
        state.systemDisconnected()
        state.ready = true
        state.connected = true
        assertNull(state.nextCommand())
    }
}
