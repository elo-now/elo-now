package now.elo.push

/** Orders app/system events while Telecom is still creating the call control. */
internal class TelecomCallState {
    enum class Command { ANSWER, DISCONNECT }
    var ready = false
    var connected = false
    var answeredBySystem = false
    @Volatile var ended = false
    private var answerStarted = false
    private var disconnectStarted = false

    fun systemDisconnected() {
        ended = true
        disconnectStarted = true
    }

    fun nextCommand(): Command? {
        if (!ready) return null
        if (ended) {
            if (disconnectStarted) return null
            disconnectStarted = true
            return Command.DISCONNECT
        }
        if (!connected || answerStarted || answeredBySystem) return null
        answerStarted = true
        return Command.ANSWER
    }
}
