import Foundation

/// Cancellation is remembered even if a delayed start has not arrived yet.
struct ForegroundRingtoneState {
    private(set) var token: String?
    private var revision: Int64 = -1
    private var deadline: Double = 0
    private var retired: [String] = []
    private var generation: UInt64 = 0

    mutating func admit(epoch: UInt64) -> Bool {
        guard epoch >= generation else { return false }
        if epoch > generation { stop(); generation = epoch }
        return true
    }

    mutating func update(token id: String, revision sequence: Int64, enabled: Bool, expires: Double, now: Double) {
        if !enabled { retire(id); return }
        guard !retired.contains(id), sequence >= 0, expires > now, expires - now <= 5_000 else { return }
        guard token != id || sequence > revision else { return }
        if token != id { if let token { retire(token) }; token = id }
        revision = sequence
        deadline = expires
    }

    mutating func live(now: Double) -> Bool {
        if token != nil && now >= deadline { stop() }
        return token != nil
    }

    mutating func stop() { if let token { retire(token) } }

    private mutating func retire(_ id: String) {
        if !retired.contains(id) { retired.append(id) }
        if retired.count > 64 { retired.removeFirst(retired.count - 64) }
        if token == id { token = nil; deadline = 0; revision = -1 }
    }
}
