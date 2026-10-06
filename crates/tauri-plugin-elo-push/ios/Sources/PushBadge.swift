import Foundation
import UserNotifications

protocol PushBadgeCenter {
    func delivered(_ completion: @escaping ([DeliveredPush]) -> Void)
    func remove(_ identifiers: [String])
    func badge(_ count: Int, completion: @escaping (Error?) -> Void)
}

private struct SystemPushBadgeCenter: PushBadgeCenter {
    let center: UNUserNotificationCenter
    func delivered(_ completion: @escaping ([DeliveredPush]) -> Void) {
        center.getDeliveredNotifications { notifications in
            completion(notifications.map {
                DeliveredPush(identifier: $0.request.identifier,
                    deliveredAt: $0.date.timeIntervalSince1970, data: $0.request.content.userInfo)
            })
        }
    }
    func remove(_ identifiers: [String]) {
        center.removeDeliveredNotifications(withIdentifiers: identifiers)
    }
    func badge(_ count: Int, completion: @escaping (Error?) -> Void) {
        center.setBadgeCount(count, withCompletionHandler: completion)
    }
}

/// Shared with the simulator harness so its test exercises the production
/// notification-center callbacks, persistence and main-queue guards.
enum PushBadge {
    private final class Generation {
        weak var prefs: UserDefaults?
        let token = UUID()
        init(_ prefs: UserDefaults) { self.prefs = prefs }
    }
    // A preferences instance owns the active profile’s hosting registrations.
    // Advancing its generation prevents old callbacks from reviving stale work.
    private static var generations: [ObjectIdentifier: Generation] = [:]

    static func invalidate(prefs: UserDefaults) {
        dispatchPrecondition(condition: .onQueue(.main))
        generations.removeValue(forKey: ObjectIdentifier(prefs))
    }

    static func reconcile(
        registration: String, unread: Bool, receipts: [[String: String]], scopes: [String],
        prefs: UserDefaults, center: UNUserNotificationCenter = .current(),
        completion: @escaping (Error?) -> Void
    ) {
        reconcile(registration: registration, unread: unread, receipts: receipts, scopes: scopes,
            prefs: prefs, center: SystemPushBadgeCenter(center: center), completion: completion)
    }

    static func reconcile(
        registration: String, unread: Bool, receipts: [[String: String]], scopes: [String],
        prefs: UserDefaults, center: PushBadgeCenter,
        completion: @escaping (Error?) -> Void
    ) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard prefs.bool(forKey: "elo.push.enabled"),
              PushRegistrations.contains(registration, prefs: prefs) else { completion(nil); return }
        generations = generations.filter { $0.value.prefs != nil }
        let identity = ObjectIdentifier(prefs)
        let generation = Generation(prefs)
        generations[identity] = generation
        let time = Date().timeIntervalSince1970
        var reads = (prefs.dictionary(forKey: "elo.push.reads") as? [String: Double] ?? [:]).filter { $0.value > time }
        for receipt in receipts.prefix(1024) {
            guard let scope = receipt["scope"], let event = receipt["event"],
                  scope.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                  event.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { continue }
            reads[scope + ":" + event] = time + 86400
        }
        for key in reads.keys.sorted(by: { reads[$0, default: 0] < reads[$1, default: 0] }).prefix(max(0, reads.count - 1024)) { reads.removeValue(forKey: key) }
        prefs.set(reads, forKey: "elo.push.reads")
        let acknowledged = reads
        center.delivered { notifications in
            DispatchQueue.main.async {
                guard prefs.bool(forKey: "elo.push.enabled"),
                      PushRegistrations.contains(registration, prefs: prefs),
                      generations[identity]?.token == generation.token else { completion(nil); return }
                let result = PushInbox.removals(notifications, registration: registration,
                    scopes: Set(scopes), reads: Set(acknowledged.keys), otherRegistrations: PushRegistrations.all(prefs).subtracting([registration]), now: Date().timeIntervalSince1970)
                center.remove(result.identifiers)
                // iOS has no dot-only badge. One indicates unread activity; it is not a message total.
                center.badge(unread || result.remaining ? 1 : 0, completion: completion)
            }
        }
    }
}
