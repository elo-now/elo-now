package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class IncomingCallStateTest {
    private val now = 1_000_000L
    private val offer = IncomingCallState.Offer("ab".repeat(16), "cd".repeat(16), "ef".repeat(16), "A".repeat(100), 1060)

    @Test fun onlyBoundedCallInvitationsCanRing() {
        for (invalid in listOf(offer.copy(callId = ""), offer.copy(invitationId = "AA".repeat(16)),
            offer.copy(registration = "../profile"), offer.copy(target = "x"), offer.copy(target = "!".repeat(100)),
            offer.copy(expires = 1000), offer.copy(expires = 1061), offer.copy(expires = Long.MAX_VALUE))) {
            assertFalse(IncomingCallState().receive(invalid, now))
        }
        val state = IncomingCallState()
        assertTrue(state.receive(offer, now))
        assertEquals(IncomingCallState.Phase.RINGING, state.active()?.phase)
        assertFalse(state.connected(offer.callId, offer.invitationId, now))
        assertEquals(listOf("incoming"), state.pending().map { it.action })
    }

    @Test fun answerWaitsForMediaAndCannotExtendTheOriginalDeadline() {
        val state = IncomingCallState()
        state.receive(offer, now)
        assertTrue(state.answer(offer.callId, offer.invitationId, now + 59_000))
        assertEquals(IncomingCallState.Phase.ANSWERING, state.active()?.phase)
        assertEquals(1_060_000L, state.active()?.deadline)
        assertFalse(state.connected(offer.callId, offer.invitationId, now + 60_000))
        assertNull(state.active())
        assertEquals(listOf("end"), state.pending().map { it.action })
    }

    @Test fun staleActionsCannotEndOrAnswerANewInvitationToTheSameCall() {
        val state = IncomingCallState()
        state.receive(offer, now)
        state.end(offer.callId, offer.invitationId, "decline", "declined", now + 1)
        assertFalse(state.receive(offer, now + 2))
        val next = offer.copy(invitationId = "12".repeat(16))
        assertTrue(state.receive(next, now + 2))
        assertFalse(state.answer(offer.callId, offer.invitationId, now + 3))
        assertFalse(state.end(offer.callId, offer.invitationId, "end", "local", now + 4))
        assertEquals(next, state.active()?.offer)
    }

    @Test fun receivingAnotherCallDoesNotReplaceTheCurrentConnection() {
        val state = IncomingCallState()
        state.receive(offer, now)
        val other = offer.copy(callId = "34".repeat(16))
        assertFalse(state.receive(other, now + 1))
        assertEquals(offer, state.active()?.offer)
        assertEquals("busy", state.pending().last().reason)
    }

    @Test fun answeredCallRequiresMediaConfirmationAndEndsAfterConnectingTimeout() {
        val state = IncomingCallState()
        state.receive(offer, now)
        assertTrue(state.answer(offer.callId, offer.invitationId, now))
        assertFalse(state.answer(offer.callId, offer.invitationId, now + 1))
        state.expire(now + 30_000)
        assertNull(state.active())
        assertFalse(state.pending().any { it.action == "answer" })
        assertEquals("expired", state.pending().last().reason)
    }

    @Test fun pendingActionsSurviveRestartButActiveMediaNeverDoes() {
        val state = IncomingCallState()
        state.receive(offer, now)
        val incoming = state.pending().single()
        val restarted = IncomingCallState()
        restarted.restore(state.snapshot(), now + 1000)
        assertEquals(incoming.eventId, restarted.pending().single().eventId)
        restarted.ack("wrong-event")
        assertEquals(1, restarted.pending().size)
        restarted.ack(incoming.eventId)
        assertTrue(restarted.pending().isEmpty())
        assertTrue(restarted.answer(offer.callId, offer.invitationId, now + 1000))
        assertTrue(restarted.connected(offer.callId, offer.invitationId, now + 2000))
        restarted.expire(now + 61_000)
        assertEquals(IncomingCallState.Phase.CONNECTED, restarted.active()?.phase)
        val cold = IncomingCallState()
        cold.restore(restarted.snapshot(), now + 62_000)
        assertNull(cold.active())
        assertEquals(listOf("end"), cold.pending().map { it.action })
        assertEquals("process_restarted", cold.pending().single().reason)
    }

    @Test fun aDeclinePersistsUntilItsExactEventIsAcknowledged() {
        val state = IncomingCallState()
        state.receive(offer, now)
        state.end(offer.callId, offer.invitationId, "decline", "declined", now + 1000)
        val restarted = IncomingCallState()
        restarted.restore(state.snapshot(), now + 2000)
        assertNull(restarted.active())
        val event = restarted.pending().single()
        assertEquals("decline", event.action)
        restarted.ack(event.eventId)
        assertTrue(restarted.pending().isEmpty())
        assertFalse(restarted.receive(offer, now + 3000))
    }

    @Test fun disablingOneHostingRegistrationPreservesOtherPendingCalls() {
        val state = IncomingCallState()
        state.receive(offer, now)
        val other = offer.copy(registration = "56".repeat(16))
        state.receive(other, now + 1)
        state.removeRegistration(other.registration, now + 2)
        assertEquals(offer, state.active()?.offer)
        assertTrue(state.pending().all { it.offer.registration == offer.registration })
        state.removeRegistration(null, now + 3)
        assertNull(state.active())
        assertTrue(state.pending().isEmpty())
    }
    @Test fun captureRequiresBothAnswerAndMatchingProcessOnlyAdmission() {
        val state = IncomingCallState()
        val media = "7b9fdc23-d773-44d2-a174-c34513416152"
        state.receive(offer, now)
        assertFalse(state.authorize(offer.callId, offer.invitationId, media, now))
        state.answer(offer.callId, offer.invitationId, now)
        assertFalse(state.authorizedMedia(media, now))
        assertFalse(state.authorize(offer.callId, "12".repeat(16), media, now))
        assertTrue(state.authorize(offer.callId, offer.invitationId, media, now))
        assertTrue(state.authorizedMedia(media, now))
        assertFalse(state.authorizedMedia("596aa1a8-ced0-43b5-9e53-8ff5ab9c9505", now))
        assertFalse(state.authorizedMedia(media, now + 30_000))
        val restarted = IncomingCallState()
        restarted.restore(state.snapshot(), now + 1000)
        assertFalse(restarted.authorizedMedia(media, now + 1000))
        state.end(offer.callId, offer.invitationId, "end", "local", now + 1000)
        assertFalse(state.authorizedMedia(media, now + 1000))
    }
    private val firstMedia = "7b9fdc23-d773-44d2-a174-c34513416152"
    private val nextMedia = "596aa1a8-ced0-43b5-9e53-8ff5ab9c9505"
    private fun connectedCall(): IncomingCallState = IncomingCallState().also {
        assertTrue(it.receive(offer, now))
        assertTrue(it.answer(offer.callId, offer.invitationId, now))
        assertTrue(it.authorize(offer.callId, offer.invitationId, firstMedia, now))
        assertTrue(it.connected(offer.callId, offer.invitationId, now))
    }
    @Test fun waitingDeclineAndExpiryKeepCurrentMediaAndExactColdAction() {
        for (declined in listOf(true, false)) {
            val state = connectedCall()
            val waiting = offer.copy(callId = "34".repeat(16), invitationId = "56".repeat(16))
            assertTrue(state.receive(waiting, now + 1))
            assertEquals(2, state.calls().size)
            assertEquals(waiting, state.active()?.offer)
            assertTrue(state.authorizedMedia(firstMedia, now + 1))
            if (declined) assertTrue(state.end(waiting.callId, waiting.invitationId, "decline", "declined", now + 2))
            else state.expire(now + 60_000)
            assertEquals(offer, state.active()?.offer)
            assertEquals(IncomingCallState.Phase.CONNECTED, state.active()?.phase)
            assertTrue(state.authorizedMedia(firstMedia, now + 61_000))
            assertEquals(waiting.key, state.pending().last().offer.key)
            assertEquals(if (declined) "decline" else "end", state.pending().last().action)
            assertFalse(state.pending().any { it.offer == waiting && it.action in listOf("incoming", "answer") })
        }
    }
    @Test fun waitingAnswerCannotCaptureUntilExactOldOwnerEnds() {
        val state = connectedCall()
        val waiting = offer.copy(invitationId = "56".repeat(16))
        assertTrue(state.receive(waiting, now + 1))
        assertTrue(state.answer(waiting.callId, waiting.invitationId, now + 2))
        assertTrue(state.authorizedMedia(firstMedia, now + 2))
        assertFalse(state.authorize(waiting.callId, waiting.invitationId, nextMedia, now + 3))
        assertFalse(state.connected(waiting.callId, waiting.invitationId, now + 3))
        assertTrue(state.end(offer.callId, offer.invitationId, "", "replaced", now + 4))
        assertFalse(state.authorizedMedia(firstMedia, now + 4))
        assertTrue(state.authorize(waiting.callId, waiting.invitationId, nextMedia, now + 5))
        assertTrue(state.connected(waiting.callId, waiting.invitationId, now + 6))
        assertFalse(state.end(offer.callId, offer.invitationId, "end", "local", now + 7))
        assertTrue(state.authorizedMedia(nextMedia, now + 7))
        assertEquals(listOf(waiting), state.calls().map { it.offer })
    }
    @Test fun thirdCallerIsBusyAndDuplicateWaitingInviteDoesNotAddEvents() {
        val state = connectedCall()
        val waiting = offer.copy(callId = "34".repeat(16))
        assertTrue(state.receive(waiting, now + 1))
        val count = state.pending().size
        assertFalse(state.receive(waiting, now + 2))
        assertEquals(count, state.pending().size)
        assertFalse(state.receive(waiting.copy(registration = "78".repeat(16)), now + 2))
        assertEquals(count, state.pending().size)
        val third = offer.copy(callId = "56".repeat(16))
        assertFalse(state.receive(third, now + 3))
        assertEquals("busy", state.pending().last().reason)
        assertEquals(third, state.pending().last().offer)
        assertEquals(listOf(offer, waiting), state.calls().map { it.offer })
        assertTrue(state.authorizedMedia(firstMedia, now + 3))
    }
    @Test fun waitingAnswerTimeoutDoesNotEndCurrentAndRestartRestoresOnlyRinging() {
        val state = connectedCall()
        val waiting = offer.copy(callId = "34".repeat(16))
        assertTrue(state.receive(waiting, now + 1))
        val restarted = IncomingCallState()
        restarted.restore(state.snapshot(), now + 2)
        assertEquals(listOf(waiting), restarted.calls().map { it.offer })
        assertFalse(restarted.authorizedMedia(firstMedia, now + 2))
        assertEquals("process_restarted", restarted.pending().last().reason)
        assertEquals(offer, restarted.pending().last().offer)
        assertTrue(state.answer(waiting.callId, waiting.invitationId, now + 3))
        state.expire(now + 30_003)
        assertEquals(offer, state.active()?.offer)
        assertTrue(state.authorizedMedia(firstMedia, now + 30_003))
        assertFalse(state.pending().any { it.offer == waiting && it.action == "answer" })
    }
    @Test fun removingWaitingRoutePreservesCurrentAndRemovingCurrentPromotesWaiting() {
        val waiting = offer.copy(callId = "34".repeat(16), registration = "56".repeat(16))
        val state = connectedCall()
        state.receive(waiting, now + 1)
        state.removeRegistration(waiting.registration, now + 2)
        assertTrue(state.authorizedMedia(firstMedia, now + 2))
        assertEquals(listOf(offer), state.calls().map { it.offer })
        assertTrue(state.pending().all { it.offer.registration == offer.registration })
        val other = connectedCall()
        other.receive(waiting, now + 1)
        other.removeRegistration(offer.registration, now + 2)
        assertEquals(listOf(waiting), other.calls().map { it.offer })
        assertFalse(other.authorizedMedia(firstMedia, now + 2))
    }

}
