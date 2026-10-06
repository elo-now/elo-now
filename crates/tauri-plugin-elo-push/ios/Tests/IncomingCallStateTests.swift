import Foundation

@main struct IncomingCallStateTests {
    static func main() {
        let now: TimeInterval = 1000
        let data: [AnyHashable: Any] = ["elo_ring": "1", "elo_call_id": String(repeating: "a", count: 32),
            "elo_invitation_id": String(repeating: "b", count: 32), "elo_registration": String(repeating: "c", count: 32),
            "elo_target": String(repeating: "x", count: 256), "elo_expires": "1060"]
        let hint = IncomingCallHint(data, now: now)!
        assert(hint.uuid.uuidString.lowercased().replacingOccurrences(of: "-", with: "") == hint.invitationId)
        for (key, invalid) in [("elo_ring", "0"), ("elo_call_id", "wrong"), ("elo_invitation_id", ""),
            ("elo_registration", String(repeating: "F", count: 32)), ("elo_target", "https://evil.invalid"),
            ("elo_target", String(repeating: "x", count: 4097)), ("elo_expires", "nan"),
            ("elo_expires", "inf"), ("elo_expires", "1000"), ("elo_expires", "1076")] {
            var value = data; value[key] = invalid
            assert(IncomingCallHint(value, now: now) == nil, "reject invalid \(key)")
        }
        var ledger = IncomingCallLedger()
        assert(!ledger.contains(hint.invitationId, now: now))
        ledger.finish(hint, now: now)
        assert(ledger.contains(hint.invitationId, now: now + 60))
        var restored = IncomingCallLedger(terminal: ledger.terminal)
        assert(restored.contains(hint.invitationId, now: now + 61))
        var next = data; next["elo_invitation_id"] = String(repeating: "d", count: 32)
        assert(!restored.contains(IncomingCallHint(next, now: now)!.invitationId, now: now))
        assert(!restored.contains(hint.invitationId, now: now + 181))
        for index in 1...200 {
            var next = data; next["elo_invitation_id"] = String(format: "%032x", index)
            ledger.finish(IncomingCallHint(next, now: now)!, now: now)
        }
        assert(ledger.terminal.count == 128)
        let capture = "12345678-1234-1234-1234-123456abcdef"
        let activation = "87654321-4321-4321-4321-fedcba654321"
        let outgoing = OutgoingSystemCall(["id": capture, "call_id": hint.callId, "activation": activation, "name": "A\nB"])!
        assert(outgoing.captureId == capture, "Keep capture spelling for exact media cleanup")
        assert(outgoing.name == "AB")
        assert(outgoing.event("mute", muted: true)["activation"] as? String == activation)
        assert(outgoing.event("mute", muted: true)["muted"] as? Bool == true)
        for key in ["id", "call_id", "activation"] {
            var request: [String: Any] = ["id": capture, "call_id": hint.callId, "activation": activation]
            request[key] = "invalid"
            assert(OutgoingSystemCall(request) == nil)
        }
        var outgoingCalls = OutgoingCallLedger()
        assert(outgoingCalls.register(outgoing))
        assert(outgoingCalls.register(outgoing), "Idempotent exact registration")
        let replacement = OutgoingSystemCall(["id": UUID().uuidString, "call_id": hint.callId, "activation": UUID().uuidString])!
        assert(!outgoingCalls.register(replacement), "No silent outgoing call replacement")
        assert(!outgoingCalls.connect(outgoing.id), "Connect cannot precede the system start action")
        assert(outgoingCalls.start(outgoing.id))
        assert(!outgoingCalls.start(outgoing.id))
        assert(outgoingCalls.connect(outgoing.id))
        assert(!outgoingCalls.connect(outgoing.id))
        assert(outgoingCalls.remove(replacement.id) == nil, "Unrelated callback cannot end capture")
        assert(outgoingCalls.remove(outgoing.id)?.captureId == capture)
        assert(outgoingCalls.register(replacement))
        assert(outgoingCalls.remove(outgoing.id) == nil, "Stale call end cannot end its successor")
        assert(outgoingCalls.call?.id == replacement.id)
        var microphone = SystemMutePolicy()
        assert(!microphone.muted(requested: false, revision: nil))
        let mute = microphone.begin()
        assert(microphone.muted(requested: false, revision: nil))
        assert(microphone.muted(requested: true, revision: mute))
        let unmute = microphone.begin()
        assert(microphone.muted(requested: false, revision: mute), "Old accepted work cannot release a new intent")
        assert(microphone.muted(requested: false, revision: nil), "Background worker has no implicit unmute grant")
        assert(!microphone.muted(requested: false, revision: unmute))
        let nextMute = microphone.begin()
        assert(microphone.muted(requested: false, revision: unmute), "Re-check after await blocks an obsolete unmute")
        assert(microphone.muted(requested: true, revision: nextMute))
        assert(microphone.muted(requested: false, revision: nil), "Old untagged work remains fenced after the latest grant")
        print("PASS: incoming hint bounds, expiry, per-attempt UUID, terminal replay after restart, bounded ledger and outgoing lifecycle identity and microphone revision fencing")
    }
}
