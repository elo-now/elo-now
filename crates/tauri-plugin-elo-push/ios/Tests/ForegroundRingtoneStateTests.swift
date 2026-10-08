import Foundation

@main struct ForegroundRingtoneStateTests {
    static func main() {
        var state = ForegroundRingtoneState()
        // A stop may reach native before the start it cancels.
        state.update(token: "cancelled", revision: 2, enabled: false, expires: 0, now: 0)
        state.update(token: "cancelled", revision: 1, enabled: true, expires: 4000, now: 0)
        assert(!state.live(now: 0))

        state.update(token: "one", revision: 1, enabled: true, expires: 4000, now: 0)
        state.update(token: "one", revision: 2, enabled: true, expires: 5500, now: 1500)
        state.update(token: "one", revision: 1, enabled: true, expires: 4000, now: 1500)
        assert(state.live(now: 5000))
        assert(!state.live(now: 5500))
        state.update(token: "one", revision: 3, enabled: true, expires: 9500, now: 5500)
        assert(!state.live(now: 5500))

        state.update(token: "two", revision: 1, enabled: true, expires: 10000, now: 6000)
        state.update(token: "one", revision: 4, enabled: false, expires: 0, now: 6000)
        assert(state.token == "two")
        state.stop()
        state.update(token: "two", revision: 2, enabled: true, expires: 11000, now: 7000)
        assert(!state.live(now: 7000))

        // Logout fences an unknown, queued start, not only the active token.
        assert(state.admit(epoch: 1))
        assert(!state.admit(epoch: 0))
        assert(state.admit(epoch: 1))
        state.update(token: "new-profile", revision: 1, enabled: true, expires: 12000, now: 8000)
        assert(state.live(now: 8000))
        assert(!state.admit(epoch: 0))
        assert(state.token == "new-profile")
        assert(state.admit(epoch: 2))
        assert(!state.live(now: 8000))

        state.update(token: "unbounded", revision: 1, enabled: true, expires: 20000, now: 8000)
        assert(!state.live(now: 8000))
        print("PASS: ringtone cancellation, revisions, renewal, expiry, lifecycle stop and native logout epochs")
    }
}
