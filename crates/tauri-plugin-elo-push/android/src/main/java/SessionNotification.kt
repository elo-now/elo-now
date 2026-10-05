package now.elo.push

/** A session hint has one original deadline; delivery cannot renew it. */
internal object SessionNotification {
    fun expiresAt(raw: String?, nowMillis: Long): Long? {
        val seconds = raw?.toLongOrNull() ?: return null
        val now = nowMillis / 1000
        if (seconds <= now || seconds > now + 60 || seconds > Long.MAX_VALUE / 1000) return null
        return seconds * 1000
    }
}
