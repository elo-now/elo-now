package now.elo.push

/** Process-only ownership for a verified call; delayed Telecom callbacks cannot replace it. */
internal class OutgoingCallState {
    data class Lease(val mediaId: String, val callId: String, val activation: String)
    private var current: Lease? = null
    private var connected = false

    fun begin(lease: Lease): Boolean {
        require(validUuid(lease.mediaId) && validUuid(lease.activation) && lease.callId.matches(Regex("[a-f0-9]{32}")))
        check(current == null || current == lease) { "unavailable" }
        if (current == lease) return false
        current = lease
        connected = false
        return true
    }
    fun active(): Lease? = current
    fun owns(lease: Lease) = current == lease
    fun connected(lease: Lease): Boolean {
        if (!owns(lease)) return false
        connected = true
        return true
    }
    fun isConnected(lease: Lease) = owns(lease) && connected
    fun end(lease: Lease): Boolean {
        if (!owns(lease)) return false
        current = null
        connected = false
        return true
    }
    private fun validUuid(value: String) = runCatching { java.util.UUID.fromString(value).toString() == value }.getOrDefault(false)
}
