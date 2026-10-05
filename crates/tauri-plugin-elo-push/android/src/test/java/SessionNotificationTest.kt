package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class SessionNotificationTest {
    @Test fun onlyTheOriginalBoundedDeadlineIsAccepted() {
        assertEquals(1_060_000L, SessionNotification.expiresAt("1060", 1_000_000))
        assertEquals(1_060_000L, SessionNotification.expiresAt("1060", 1_059_000))
        assertNull(SessionNotification.expiresAt("1060", 1_060_000))
        for (value in listOf(null, "", "invalid", "1000", "999", "1061", Long.MAX_VALUE.toString())) {
            assertNull(SessionNotification.expiresAt(value, 1_000_000))
        }
    }
}
