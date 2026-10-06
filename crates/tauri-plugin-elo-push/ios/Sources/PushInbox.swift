import Foundation

/// A notification-center entry is only a hint until the unlocked profile verifies it.
struct DeliveredPush {
    let identifier: String
    let deliveredAt: TimeInterval
    let data: [AnyHashable: Any]
}

enum PushInbox {
    static let lifetime: TimeInterval = 86_400

    static func isExpired(_ entry: DeliveredPush, now: TimeInterval) -> Bool {
        if entry.data["elo_category"] as? String == "session_start" {
            guard let raw = entry.data["elo_expires"] as? String,
                  let expires = TimeInterval(raw), expires.isFinite,
                  expires > now, expires <= now + 60 else { return true }
            return false
        }
        return now - entry.deliveredAt >= lifetime
    }

    static func removals(
        _ entries: [DeliveredPush], registration: String, scopes: Set<String>,
        reads: Set<String>, otherRegistrations: Set<String> = [], now: TimeInterval
    ) -> (identifiers: [String], remaining: Bool) {
        var identifiers: [String] = []
        var remaining = false
        for entry in entries {
            let data = entry.data
            guard data["elo_wake"] as? String == "1", let scope = data["elo_scope"] as? String else { continue }
            let event = data["elo_event"] as? String ?? ""
            if let other = data["elo_registration"] as? String, otherRegistrations.contains(other) {
                if isExpired(entry, now: now) || reads.contains(scope + ":" + event) { identifiers.append(entry.identifier) }
                else if data["elo_category"] as? String != "session_start" { remaining = true }
                continue
            }
            if data["elo_registration"] as? String != registration || !scopes.contains(scope)
                || reads.contains(scope + ":" + event) || isExpired(entry, now: now) {
                identifiers.append(entry.identifier)
            } else {
                // Keep a new push whose message has not reached local sync yet.
                if data["elo_category"] as? String != "session_start" { remaining = true }
            }
        }
        return (identifiers, remaining)
    }

    static func pendingMessages(
        _ entries: [DeliveredPush], registration: String, reads: Set<String>, now: TimeInterval
    ) -> [[String: String]] {
        var result: [[String: String]] = []
        for entry in entries {
            let data = entry.data
            guard data["elo_registration"] as? String == registration,
                  data["elo_wake"] as? String == "1", data["elo_category"] as? String == "message",
                  !isExpired(entry, now: now),
                  let scope = data["elo_scope"] as? String, isDigest(scope),
                  let event = data["elo_event"] as? String, isDigest(event),
                  !reads.contains(scope + ":" + event),
                  let target = data["elo_target"] as? String, (64...2048).contains(target.utf8.count),
                  target.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else { continue }
            result.append(["scope": scope, "event": event, "target": target])
            if result.count == 64 { break }
        }
        return result
    }

    private static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
    }
}
