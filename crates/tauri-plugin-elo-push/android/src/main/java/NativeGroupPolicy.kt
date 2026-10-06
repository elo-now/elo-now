package now.elo.push

/** A room can be retried, but an old membership epoch can never be restored. */
internal class NativeGroupPolicy {
    var epoch: Long = 0
        private set
    var members: Set<String> = emptySet()
        private set
    var credential: String = ""
        private set
    private var keyDigest: ByteArray? = null

    fun accept(nextEpoch: Long, key: String, participants: List<String>, local: String) {
        require(nextEpoch > 0 && nextEpoch >= epoch && key.matches(Regex("[a-f0-9]{64}")))
        val nextMembers = participants.toSet()
        require(participants.size in 1..256 && nextMembers.size == participants.size && local in nextMembers &&
            nextMembers.all { it.matches(Regex("[a-f0-9]{32,128}")) })
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.US_ASCII))
        if (nextEpoch == epoch) require(nextMembers == members && local == credential && keyDigest?.contentEquals(digest) == true)
        else if (epoch != 0L) require(keyDigest?.contentEquals(digest) == false)
        epoch = nextEpoch; members = nextMembers; credential = local; keyDigest = digest
    }
    fun maySubscribe(identity: String?, encrypted: Boolean) = encrypted && identity != null && identity in members && identity != credential
}
