package now.elo.push

/** An OS unmute request stays locally muted until its exact signed result returns. */
internal class SystemMuteState {
    private var owner: String? = null
    private var revision = 0L
    private var blocked = false

    @Synchronized fun request(id: String, silence: () -> Unit): Long {
        owner = id
        revision += 1
        blocked = true
        silence()
        return revision
    }
    @Synchronized fun blocked(id: String) = owner == id && blocked
    @Synchronized fun applyUpdate(id: String, approved: Long, apply: (Boolean) -> Unit): Boolean {
        val permitted = owner == null || (owner == id && approved == revision)
        // Recheck on each update, including after asynchronous group work: an
        // old worker must not undo a newer OS request or its accepted state.
        apply(!permitted)
        if (owner == id && permitted) blocked = false
        return permitted
    }
    @Synchronized fun end(id: String? = null) {
        if (id == null || owner == id) { owner = null; blocked = false }
    }
}
