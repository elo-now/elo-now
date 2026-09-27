// Copyright 2026 elo.now contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

package {{package}}

/** Foreground-only, bounded recovery; no timers run while the app is hidden. */
internal class RendererRecovery {
    enum class Action { NONE, RECREATE, CLOSE }
    private var pending = false
    private val attempts = ArrayDeque<Long>()

    fun terminated() { pending = true }

    fun nextAction(visible: Boolean, now: Long): Action {
        if (!pending || !visible) return Action.NONE
        pending = false
        while (attempts.isNotEmpty() && now - attempts.first() >= 30_000) {
            attempts.removeFirst()
        }
        if (attempts.size >= 2) return Action.CLOSE
        attempts.addLast(now)
        return Action.RECREATE
    }
}
