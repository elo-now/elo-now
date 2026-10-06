import Foundation

// Run with swiftc Sources/PushInbox.swift Tests/PushInboxTests.swift -o <temporary executable>.
@main
struct PushInboxTests {
    static func main() {
        let scope = String(repeating: "a", count: 64)
        let event = String(repeating: "b", count: 64)
        let nextEvent = String(repeating: "c", count: 64)
        let now: TimeInterval = 100_000
        let data: [AnyHashable: Any] = ["elo_registration": "current", "elo_wake": "1",
            "elo_category": "message", "elo_scope": scope, "elo_event": event,
            "elo_target": String(repeating: "X", count: 128)]
        let read = DeliveredPush(identifier: "read", deliveredAt: now - 2, data: data)
        var nextData = data
        nextData["elo_event"] = nextEvent
        let unseen = DeliveredPush(identifier: "not-synced-yet", deliveredAt: now - 1, data: nextData)
        let acknowledgement: Set<String> = [scope + ":" + event]
        let result = PushInbox.removals([read, unseen], registration: "current", scopes: [scope], reads: acknowledgement, now: now)
        assert(result.identifiers == ["read"] && result.remaining, "Reading one event must preserve a newer, unsynced push")
        let cleared = PushInbox.removals([read], registration: "current", scopes: [scope], reads: acknowledgement, now: now)
        assert(cleared.identifiers == ["read"] && !cleared.remaining, "The last acknowledged push must not keep the badge")

        let expired = DeliveredPush(identifier: "expired", deliveredAt: now - PushInbox.lifetime, data: data)
        let expiredResult = PushInbox.removals([expired], registration: "current", scopes: [scope], reads: [], now: now)
        assert(expiredResult.identifiers == ["expired"] && !expiredResult.remaining, "An old notification must not outlive its bounded receipt retention")
        let recent = DeliveredPush(identifier: "recent", deliveredAt: now - PushInbox.lifetime + 1, data: data)
        assert(PushInbox.removals([recent], registration: "current", scopes: [scope], reads: [], now: now).remaining)

        var oldData = data
        oldData["elo_registration"] = "previous-profile"
        let old = DeliveredPush(identifier: "old-profile", deliveredAt: now, data: oldData)
        let local = DeliveredPush(identifier: "reminder", deliveredAt: 0, data: [:])
        assert(PushInbox.removals([old, local], registration: "current", scopes: [scope], reads: [], now: now).identifiers == ["old-profile"], "Cleanup must not remove local reminders")
        assert(PushInbox.removals([unseen], registration: "current", scopes: [], reads: [], now: now).identifiers == ["not-synced-yet"], "Notifications from removed scopes must be cleared")

        var privateData = data
        privateData["elo_registration"] = "private-host"
        let privateMessage = DeliveredPush(identifier: "private-host-message", deliveredAt: now, data: privateData)
        let isolated = PushInbox.removals([read, privateMessage, old], registration: "current", scopes: [], reads: [], otherRegistrations: ["private-host"], now: now)
        assert(isolated.identifiers == ["read", "old-profile"] && isolated.remaining, "Updating one hosting must retain unread notifications from another active hosting")
        assert(PushInbox.pendingMessages([privateMessage], registration: "current", reads: [], now: now).isEmpty, "A host must not receive another host's delivered targets")

        let pending = PushInbox.pendingMessages([read, unseen, expired, old, local], registration: "current", reads: acknowledgement, now: now)
        assert(pending.count == 1 && pending[0]["event"] == nextEvent, "Only unacknowledged current message targets go to the unlocked verifier")
        assert(PushInbox.pendingMessages([read], registration: "current", reads: [], now: now).count == 1, "A lost receipt must be recoverable from the delivered target")
        for (key, value) in [("elo_target", "invalid?"), ("elo_target", String(repeating: "X", count: 2049)),
                             ("elo_scope", "invalid"), ("elo_event", "invalid"), ("elo_category", "invitation")] {
            var invalid = data
            invalid[key] = value
            let entry = DeliveredPush(identifier: "invalid", deliveredAt: now, data: invalid)
            assert(PushInbox.pendingMessages([entry], registration: "current", reads: [], now: now).isEmpty)
            assert(PushInbox.removals([entry], registration: "current", scopes: [scope, "invalid"], reads: [], now: now).remaining,
                "An unverified target must not be silently treated as read")
        }
        let batch = Array(repeating: unseen, count: 65)
        assert(PushInbox.pendingMessages(batch, registration: "current", reads: [], now: now).count == 64)
        assert(PushInbox.removals(batch, registration: "current", scopes: [scope], reads: [], now: now).remaining)
        var sessionData = data
        sessionData["elo_category"] = "session_start"
        sessionData["elo_expires"] = "100060"
        let session = DeliveredPush(identifier: "session", deliveredAt: now, data: sessionData)
        let liveSession = PushInbox.removals([session], registration: "current", scopes: [scope], reads: [], now: now)
        assert(liveSession.identifiers.isEmpty && !liveSession.remaining, "A voluntary session hint must not create an unread-message badge")
        assert(PushInbox.isExpired(session, now: now + 60), "A delivered session hint must expire after its original 60-second deadline")
        assert(PushInbox.pendingMessages([session], registration: "current", reads: [], now: now).isEmpty)
        for invalid in ["100061", "100000", "invalid", "nan", "inf"] {
            sessionData["elo_expires"] = invalid
            assert(PushInbox.isExpired(DeliveredPush(identifier: "invalid-session", deliveredAt: now, data: sessionData), now: now))
        }
        print("PASS: iOS badge cleanup, late pushes, receipt recovery, expiry, profile isolation and bounded verification")
    }
}
