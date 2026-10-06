package now.elo.push

import org.junit.Assert.*
import org.junit.Test

class NativeGroupPolicyTest {
    private val local = "a1".repeat(32)
    private val remote = "b2".repeat(32)
    private val key = "12".repeat(32)
    @Test fun retryAcceptsOnlyTheSameKeyAndSignedParticipants() {
        val policy = NativeGroupPolicy()
        policy.accept(1, key, listOf(local, remote), local)
        policy.accept(1, key, listOf(remote, local), local)
        assertThrows(IllegalArgumentException::class.java) { policy.accept(1, "34".repeat(32), listOf(local, remote), local) }
        assertThrows(IllegalArgumentException::class.java) { policy.accept(1, key, listOf(local), local) }
        assertTrue(policy.maySubscribe(remote, true))
        assertFalse(policy.maySubscribe(remote, false))
        assertFalse(policy.maySubscribe("c3".repeat(32), true))
        assertFalse(policy.maySubscribe(local, true))
    }
    @Test fun advancingMembershipRequiresANewKeyAndRejectsOldEpochs() {
        val policy = NativeGroupPolicy()
        policy.accept(1, key, listOf(local, remote), local)
        assertThrows(IllegalArgumentException::class.java) { policy.accept(2, key, listOf(local), local) }
        policy.accept(2, "34".repeat(32), listOf(local), local)
        assertFalse(policy.maySubscribe(remote, true))
        assertThrows(IllegalArgumentException::class.java) { policy.accept(1, key, listOf(local, remote), local) }
    }
    @Test fun malformedKeysOrMissingLocalMembershipNeverInitializeTheRoom() {
        val policy = NativeGroupPolicy()
        assertThrows(IllegalArgumentException::class.java) { policy.accept(1, "12", listOf(local, remote), local) }
        assertThrows(IllegalArgumentException::class.java) { policy.accept(1, key, listOf(remote), local) }
        assertThrows(IllegalArgumentException::class.java) { policy.accept(1, key, listOf(local, local), local) }
        assertEquals(0L, policy.epoch)
    }
}
