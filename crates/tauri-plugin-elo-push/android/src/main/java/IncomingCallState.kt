package now.elo.push

/** Notification delivery and a user's answer are not proof of an established call. */
internal class IncomingCallState {
    data class Offer(val callId: String, val invitationId: String, val registration: String, val target: String, val expires: Long) {
        val key: String get() = "$registration:$callId:$invitationId"
        fun valid(now: Long): Boolean = HEX.matches(callId) && HEX.matches(invitationId) && HEX.matches(registration) &&
            target.length in 64..4096 && TARGET.matches(target) && expires > now / 1000 && expires <= now / 1000 + 60
    }
    enum class Phase { RINGING, ANSWERING, CONNECTED }
    data class Call(val offer: Offer, val phase: Phase, val deadline: Long)
    data class Event(val eventId: String, val action: String, val offer: Offer, val createdAt: Long, val reason: String? = null)
    data class Snapshot(val call: Call?, val pending: List<Event>, val seen: Map<String, Long>, val waiting: Call? = null)

    private var call: Call? = null
    private var waiting: Call? = null
    private val events = mutableListOf<Event>()
    private val seen = linkedMapOf<String, Long>()
    private var mediaAuthorization: Pair<String, String>? = null

    fun active(): Call? = waiting ?: call
    fun calls(): List<Call> = listOfNotNull(call, waiting)
    fun matching(callId: String, invitationId: String) = calls().firstOrNull { it.offer.callId == callId && it.offer.invitationId == invitationId }
    fun pending(): List<Event> = events.toList()
    fun snapshot() = Snapshot(call, pending(), seen.toMap(), waiting)
    fun restore(snapshot: Snapshot, now: Long) {
        mediaAuthorization = null
        call = snapshot.call
        waiting = snapshot.waiting
        events.clear()
        events.addAll(snapshot.pending.takeLast(MAX_EVENTS))
        seen.clear()
        seen.putAll(snapshot.seen.entries.toList().takeLast(MAX_SEEN).associate { it.toPair() })
        // A terminated process has no media engine or live Telecom connection.
        calls().forEach {
            if (it.phase != Phase.RINGING) finish(it, "end", "process_restarted", now)
            else if (!it.offer.valid(now)) finish(it, "end", "expired", now)
        }
        expire(now)
    }
    fun receive(offer: Offer, now: Long): Boolean {
        expire(now)
        if (!offer.valid(now) || offer.key in seen) return false
        seen[offer.key] = now + RETAIN_MS
        while (seen.size > MAX_SEEN) seen.remove(seen.keys.first())
        if (matching(offer.callId, offer.invitationId) != null) return false
        if (call != null && (call?.phase != Phase.CONNECTED || waiting != null)) {
            enqueue("decline", offer, now, "busy")
            return false
        }
        val incoming = Call(offer, Phase.RINGING, offer.expires * 1000)
        if (call == null) call = incoming else waiting = incoming
        enqueue("incoming", offer, now)
        return true
    }
    fun answer(callId: String, invitationId: String, now: Long): Boolean {
        expire(now)
        val active = matching(callId, invitationId) ?: return false
        if (active.phase != Phase.RINGING) return false
        replace(active.copy(phase = Phase.ANSWERING, deadline = minOf(active.deadline, now + 30_000)))
        enqueue("answer", active.offer, now)
        return true
    }
    fun connected(callId: String, invitationId: String, now: Long): Boolean {
        expire(now)
        val active = matching(callId, invitationId) ?: return false
        if (active.phase != Phase.ANSWERING) return false
        if (active === waiting && call != null) return false
        replace(active.copy(phase = Phase.CONNECTED, deadline = Long.MAX_VALUE))
        return true
    }
    fun authorize(callId: String, invitationId: String, mediaId: String, now: Long): Boolean {
        expire(now)
        val active = matching(callId, invitationId) ?: return false
        if (active.phase == Phase.RINGING || !runCatching { java.util.UUID.fromString(mediaId).toString() == mediaId }.getOrDefault(false)) return false
        // Answering a waiting call grants no capture until the old owner has ended.
        if (active === waiting && call != null) return false
        val requested = active.offer.key to mediaId
        if (mediaAuthorization != null && mediaAuthorization != requested) return false
        mediaAuthorization = requested
        return true
    }
    fun authorizedCall(mediaId: String, now: Long): Call? = calls().firstOrNull {
        it.phase != Phase.RINGING && it.deadline > now && mediaAuthorization == (it.offer.key to mediaId)
    }
    fun authorizedMedia(mediaId: String, now: Long): Boolean = authorizedCall(mediaId, now) != null
    fun end(callId: String, invitationId: String, action: String, reason: String?, now: Long): Boolean {
        val active = matching(callId, invitationId) ?: return false
        finish(active, action, reason, now)
        return true
    }
    fun removeRegistration(registration: String?, now: Long) {
        calls().filter { registration == null || it.offer.registration == registration }.forEach { finish(it, "end", "disabled", now) }
        events.removeAll { registration == null || it.offer.registration == registration }
        seen.keys.removeAll { registration == null || it.startsWith("$registration:") }
    }
    fun ack(eventId: String) { events.removeAll { it.eventId == eventId } }
    fun expire(now: Long) {
        calls().filter { it.deadline <= now }.forEach { finish(it, "end", "expired", now) }
        events.removeAll { it.createdAt < now - RETAIN_MS || it.createdAt > now + 60_000 }
        seen.entries.removeAll { it.value <= now || it.value > now + RETAIN_MS }
    }
    private fun replace(updated: Call) {
        if (call?.offer?.key == updated.offer.key) call = updated
        else if (waiting?.offer?.key == updated.offer.key) waiting = updated
    }
    private fun finish(active: Call, action: String, reason: String?, now: Long) {
        if (call?.offer?.key == active.offer.key) { call = waiting; waiting = null }
        else if (waiting?.offer?.key == active.offer.key) waiting = null
        else return
        if (mediaAuthorization?.first == active.offer.key) mediaAuthorization = null
        // An answer waiting for a consumer must not resurrect an ended call.
        events.removeAll { it.offer.key == active.offer.key && it.action in listOf("incoming", "answer") }
        if (action != "") enqueue(action, active.offer, now, reason)
    }
    private fun enqueue(action: String, offer: Offer, now: Long, reason: String? = null) {
        events += Event(java.util.UUID.randomUUID().toString(), action, offer, now, reason)
        while (events.size > MAX_EVENTS) events.removeAt(0)
    }
    companion object {
        private val HEX = Regex("[a-f0-9]{32}")
        private val TARGET = Regex("[A-Za-z0-9_-]+")
        private const val RETAIN_MS = 300_000L
        private const val MAX_EVENTS = 32
        private const val MAX_SEEN = 256
    }
}
