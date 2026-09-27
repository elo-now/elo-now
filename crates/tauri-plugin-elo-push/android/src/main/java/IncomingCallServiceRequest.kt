package now.elo.push

/** A persisted call alone never authorizes a foreground service after a restart. */
internal object IncomingCallServiceRequest {
    const val ACTION = "now.elo.push.UPDATE_INCOMING_CALL"
    const val CALL_ID = "call_id"

    fun isAllowed(action: String?, requestedId: String?, currentId: String?, telecomReady: Boolean): Boolean =
        action == ACTION && !requestedId.isNullOrBlank() && requestedId == currentId && telecomReady
}
