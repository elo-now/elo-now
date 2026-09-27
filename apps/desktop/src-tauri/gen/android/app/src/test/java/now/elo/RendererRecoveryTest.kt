package now.elo

import org.junit.Assert.assertEquals
import org.junit.Test

class RendererRecoveryTest {
    @Test fun terminationInBackgroundWaitsForForeground() {
        val recovery = RendererRecovery()
        recovery.terminated()
        assertEquals(RendererRecovery.Action.NONE, recovery.nextAction(false, 0))
        assertEquals(RendererRecovery.Action.NONE, recovery.nextAction(false, 60_000))
        assertEquals(RendererRecovery.Action.RECREATE, recovery.nextAction(true, 60_001))
        assertEquals(RendererRecovery.Action.NONE, recovery.nextAction(true, 60_002))
    }

    @Test fun repeatedStartupCrashesCannotCreateAnInfiniteLoop() {
        val recovery = RendererRecovery()
        repeat(2) { n ->
            recovery.terminated()
            assertEquals(RendererRecovery.Action.RECREATE, recovery.nextAction(true, n.toLong()))
        }
        recovery.terminated()
        assertEquals(RendererRecovery.Action.CLOSE, recovery.nextAction(true, 2))
        assertEquals(RendererRecovery.Action.NONE, recovery.nextAction(true, 3))
    }

    @Test fun AnIsolatedLaterCrashCanRecoverAgain() {
        val recovery = RendererRecovery()
        repeat(2) { n ->
            recovery.terminated()
            recovery.nextAction(true, n.toLong())
        }
        recovery.terminated()
        assertEquals(RendererRecovery.Action.RECREATE, recovery.nextAction(true, 30_000))
    }
}
