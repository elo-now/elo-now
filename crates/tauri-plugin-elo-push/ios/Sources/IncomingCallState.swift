import Foundation

/// Bounds transport hints before CallKit sees them. Authorization and media
/// admission still happen in Rust; a notification never grants microphone access.
struct IncomingCallHint: Equatable {
    let callId: String
    let invitationId: String
    let registration: String
    let target: String
    let expires: TimeInterval

    init?(_ data: [AnyHashable: Any], now: TimeInterval) {
        func hex(_ value: String?) -> String? {
            guard let value, value.count == 32,
                  value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
            return value
        }
        guard data["elo_ring"] as? String == "1",
              let callId = hex(data["elo_call_id"] as? String),
              let invitationId = hex(data["elo_invitation_id"] as? String),
              let registration = hex(data["elo_registration"] as? String),
              let target = data["elo_target"] as? String,
              (64...4096).contains(target.utf8.count),
              target.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }),
              let raw = data["elo_expires"] as? String, let expires = TimeInterval(raw),
              expires.isFinite, expires > now, expires <= now + 75 else { return nil }
        self.callId = callId; self.invitationId = invitationId
        self.registration = registration; self.target = target; self.expires = expires
    }

    var uuid: UUID {
        let text = invitationId
        let parts = [(0, 8), (8, 4), (12, 4), (16, 4), (20, 12)].map { start, length in
            String(text.dropFirst(start).prefix(length))
        }
        return UUID(uuidString: parts.joined(separator: "-"))!
    }

    func event(_ action: String) -> [String: Any] {
        ["action": action, "callId": callId, "invitationId": invitationId,
         "registration": registration, "target": target, "expires": expires]
    }
}

/// One bounded ledger per installation prevents repeated transport delivery from
/// reopening a call the user already rejected, including after process restart.
struct IncomingCallLedger {
    private(set) var terminal: [String: TimeInterval]
    init(terminal: [String: TimeInterval] = [:]) { self.terminal = terminal }
    mutating func contains(_ id: String, now: TimeInterval) -> Bool {
        terminal = terminal.filter { $0.value > now }
        return terminal[id] != nil
    }
    mutating func finish(_ hint: IncomingCallHint, now: TimeInterval) {
        terminal = terminal.filter { $0.value > now }
        terminal[hint.invitationId] = max(hint.expires, now) + 120
        while terminal.count > 128,
              let oldest = terminal.min(by: { $0.value < $1.value })?.key {
            terminal.removeValue(forKey: oldest)
        }
    }
}

/// Outgoing calls are registered only after Rust has verified signed membership.
/// Capture UUID and activation distinguish an old session from its replacement.
struct OutgoingSystemCall: Equatable {
    let id: UUID
    let captureId: String
    let callId: String
    let activation: String
    let name: String
    var started = false
    var connected = false

    init?(_ request: [String: Any]) {
        guard let rawId = request["id"] as? String, let id = UUID(uuidString: rawId),
              let callId = request["call_id"] as? String, callId.count == 32,
              callId.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let activation = request["activation"] as? String, UUID(uuidString: activation) != nil else { return nil }
        self.id = id; self.captureId = rawId; self.callId = callId; self.activation = activation
        let supplied = request["name"] as? String ?? "elo.now"
        let label = String(supplied.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(120))
        name = label.isEmpty ? "elo.now" : label
    }

    func matches(_ other: OutgoingSystemCall) -> Bool {
        id == other.id && callId == other.callId && activation == other.activation
    }
    func event(_ action: String, muted: Bool? = nil) -> [String: Any] {
        var value: [String: Any] = ["sessionId": callId, "activation": activation, "action": action]
        if let muted { value["muted"] = muted }
        return value
    }
}

struct OutgoingCallLedger {
    private(set) var call: OutgoingSystemCall?
    mutating func register(_ value: OutgoingSystemCall) -> Bool {
        if let call { return call.matches(value) }
        call = value
        return true
    }
    mutating func start(_ id: UUID) -> Bool {
        guard call?.id == id, call?.started == false else { return false }
        call?.started = true
        return true
    }
    mutating func connect(_ id: UUID) -> Bool {
        guard call?.id == id, call?.started == true, call?.connected == false else { return false }
        call?.connected = true
        return true
    }
    mutating func remove(_ id: UUID) -> OutgoingSystemCall? {
        guard call?.id == id else { return nil }
        defer { call = nil }
        return call
    }
}

/// Every system microphone intent replaces the previous one. Updates carry the
/// exact revision accepted by the signed runtime; old async work stays muted.
struct SystemMutePolicy {
    private(set) var revision: UInt64 = 0
    mutating func begin() -> UInt64 {
        revision = revision == UInt64.max ? 1 : revision + 1
        return revision
    }
    func muted(requested: Bool, revision supplied: UInt64?) -> Bool {
        requested || (revision != 0 && supplied != revision)
    }
}
