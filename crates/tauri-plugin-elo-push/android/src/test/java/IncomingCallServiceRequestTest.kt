package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class IncomingCallServiceRequestTest {
    private val callId = "a".repeat(32)

    @Test fun bootBroadcastsCannotPromoteEvenWithPersistedCallAndLiveTelecom() {
        for (action in listOf(
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.LOCKED_BOOT_COMPLETED",
            "android.intent.action.QUICKBOOT_POWERON",
        )) {
            assertFalse(IncomingCallServiceRequest.isAllowed(action, callId, callId, true))
        }
    }

    @Test fun nullRestartCannotRestorePersistedCall() {
        assertFalse(IncomingCallServiceRequest.isAllowed(null, null, callId, false))
    }

    @Test fun persistedConnectedCallWithoutProcessOwnedTelecomCannotRestartService() {
        assertFalse(IncomingCallServiceRequest.isAllowed(IncomingCallServiceRequest.ACTION, callId, callId, false))
    }

    @Test fun queuedUpdateForPreviousCallCannotStartNewCallService() {
        assertFalse(IncomingCallServiceRequest.isAllowed(IncomingCallServiceRequest.ACTION, callId, "b".repeat(32), true))
    }

    @Test fun removedCallCannotBeResurrectedByQueuedUpdate() {
        assertFalse(IncomingCallServiceRequest.isAllowed(IncomingCallServiceRequest.ACTION, callId, null, false))
    }

    @Test fun missingCallIdentifierIsRejected() {
        assertFalse(IncomingCallServiceRequest.isAllowed(IncomingCallServiceRequest.ACTION, null, callId, true))
        assertFalse(IncomingCallServiceRequest.isAllowed(IncomingCallServiceRequest.ACTION, "", "", true))
    }

    @Test fun currentTelecomCallCanStartAndUpdateNotification() {
        repeat(3) {
            assertTrue(IncomingCallServiceRequest.isAllowed(IncomingCallServiceRequest.ACTION, callId, callId, true))
        }
    }
}
