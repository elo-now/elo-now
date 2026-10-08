package now.elo.push

/** Short leases and cancellation tombstones fence delayed WebView callbacks. */
internal class ForegroundRingtoneState {
    var token: String? = null
        private set
    private var revision = -1L
    private var deadline = 0L
    private val retired = linkedSetOf<String>()
    private var generation = 0L

    fun admit(epoch: Long): Boolean {
        if (epoch < generation) return false
        if (epoch > generation) { stop(); generation = epoch }
        return true
    }

    fun update(id: String, sequence: Long, enabled: Boolean, expires: Long, now: Long): Boolean {
        if (!enabled) { retire(id); return false }
        if (id in retired || sequence < 0 || expires <= now || expires - now > 5_000) return false
        if (token == id && sequence <= revision) return false
        if (token != id) { token?.let(::retire); token = id }
        revision = sequence
        deadline = expires
        return true
    }

    fun live(now: Long): Boolean {
        if (token != null && now >= deadline) stop()
        return token != null
    }

    fun stop() { token?.let(::retire) }

    private fun retire(id: String) {
        retired += id
        while (retired.size > 64) retired.remove(retired.first())
        if (token == id) { token = null; deadline = 0; revision = -1 }
    }
}
