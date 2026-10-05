import Foundation

private final class Center: PushBadgeCenter {
    var callbacks: [([DeliveredPush]) -> Void] = []
    var removals: [[String]] = []
    var badges: [Int] = []
    var error: Error?
    func delivered(_ completion: @escaping ([DeliveredPush]) -> Void) { callbacks.append(completion) }
    func remove(_ identifiers: [String]) { removals.append(identifiers) }
    func badge(_ count: Int, completion: @escaping (Error?) -> Void) {
        badges.append(count)
        completion(error)
    }
}

@main
struct PushBadgeOrderingTests {
    static let registration = String(repeating: "1", count: 32)
    static let scope = String(repeating: "a", count: 64)
    static let event = String(repeating: "b", count: 64)

    @MainActor static func main() async {
        let suite = "now.elo.badge-ordering." + UUID().uuidString
        let secondSuite = suite + ".second"
        let prefs = UserDefaults(suiteName: suite)!
        let other = UserDefaults(suiteName: secondSuite)!
        defer {
            PushBadge.invalidate(prefs: prefs)
            PushBadge.invalidate(prefs: other)
            prefs.removePersistentDomain(forName: suite)
            other.removePersistentDomain(forName: secondSuite)
        }
        for store in [prefs, other] {
            store.set(true, forKey: "elo.push.enabled")
            store.set(registration, forKey: "elo.push.registration")
        }
        let notification = DeliveredPush(identifier: "already-read",
            deliveredAt: Date().timeIntervalSince1970,
            data: ["elo_registration": registration, "elo_wake": "1", "elo_scope": scope, "elo_event": event])

        // Force the newer snapshot to return before the old unread snapshot.
        let reordered = Center()
        await withCheckedContinuation { (finished: CheckedContinuation<Void, Never>) in
            var completions = 0
            let complete: (Error?) -> Void = { error in
                precondition(error == nil)
                completions += 1
                if completions == 2 { finished.resume() }
            }
            PushBadge.reconcile(registration: registration, unread: true, receipts: [], scopes: [scope],
                prefs: prefs, center: reordered, completion: complete)
            PushBadge.reconcile(registration: registration, unread: false,
                receipts: [["scope": scope, "event": event]], scopes: [scope],
                prefs: prefs, center: reordered, completion: complete)
            reordered.callbacks[1]([notification])
            reordered.callbacks[0]([notification])
        }
        precondition(reordered.badges == [0], "A stale callback must not restore badge 1")
        precondition(reordered.removals == [["already-read"]], "A stale callback must not remove notifications")

        // Separate preferences instances must not invalidate one another.
        let firstCenter = Center()
        let secondCenter = Center()
        await withCheckedContinuation { (finished: CheckedContinuation<Void, Never>) in
            var completions = 0
            let complete: (Error?) -> Void = { error in
                precondition(error == nil)
                completions += 1
                if completions == 2 { finished.resume() }
            }
            PushBadge.reconcile(registration: registration, unread: true, receipts: [], scopes: [],
                prefs: prefs, center: firstCenter, completion: complete)
            PushBadge.reconcile(registration: registration, unread: false, receipts: [], scopes: [],
                prefs: other, center: secondCenter, completion: complete)
            secondCenter.callbacks[0]([])
            firstCenter.callbacks[0]([])
        }
        precondition(firstCenter.badges == [1] && secondCenter.badges == [0])

        // Plugin register/disable invalidation also protects an A -> B -> A switch.
        let switched = Center()
        await withCheckedContinuation { (finished: CheckedContinuation<Void, Never>) in
            PushBadge.reconcile(registration: registration, unread: true, receipts: [], scopes: [],
                prefs: prefs, center: switched) { error in
                precondition(error == nil)
                finished.resume()
            }
            PushBadge.invalidate(prefs: prefs)
            prefs.set("different-registration", forKey: "elo.push.registration")
            prefs.set(registration, forKey: "elo.push.registration")
            switched.callbacks[0]([])
        }
        precondition(switched.badges.isEmpty && switched.removals.isEmpty)

        let failed = Center()
        failed.error = NSError(domain: "SyntheticBadgeFailure", code: 1)
        await withCheckedContinuation { (finished: CheckedContinuation<Void, Never>) in
            PushBadge.reconcile(registration: registration, unread: false, receipts: [], scopes: [],
                prefs: prefs, center: failed) { error in
                precondition((error as NSError?)?.domain == "SyntheticBadgeFailure")
                finished.resume()
            }
            failed.callbacks[0]([])
        }
        print("PASS: reordered callbacks, preferences isolation, registration invalidation and error completion")
    }
}
