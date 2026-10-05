import Foundation
import UIKit
import UserNotifications

/// Built only by tools/check_ios_badge.py, with a separate bundle/container.
@main
final class BadgeHarness: UIResponder, UIApplicationDelegate {}

final class BadgeHarnessScene: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private let prefs = UserDefaults.standard
    private let center = UNUserNotificationCenter.current()
    private let registration = String(repeating: "1", count: 32)
    private let scope = String(repeating: "a", count: 64)
    private let eventA = String(repeating: "b", count: 64)
    private let eventB = String(repeating: "c", count: 64)
    private let eventC = String(repeating: "d", count: 64)

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: scene)
        let controller = UIViewController()
        controller.view.backgroundColor = .systemBackground
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window
        let phase = ProcessInfo.processInfo.arguments.last ?? "missing"
        print("HARNESS started phase \(phase)")
        fflush(stdout)
        Task { @MainActor in
            do {
                try await run(phase)
                finish(phase, error: nil)
            } catch { finish(phase, error: String(describing: error)) }
        }
    }

    struct Failure: Error, CustomStringConvertible {
        let description: String
    }
    private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw Failure(description: message) }
    }
    @MainActor private func finish(_ phase: String, error: String?) {
        let result: [String: Any] = ["phase": phase, "passed": error == nil,
            "error": error ?? "", "system_badge": UIApplication.shared.applicationIconBadgeNumber]
        let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        do {
            let bytes = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            try bytes.write(to: directory.appendingPathComponent(phase + ".json"), options: .atomic)
            print(String(data: bytes, encoding: .utf8)!)
        } catch { print("FAIL: could not record harness result: \(error)") }
    }
    private func delivered() async -> [UNNotification] {
        await withCheckedContinuation { continuation in
            center.getDeliveredNotifications { continuation.resume(returning: $0) }
        }
    }
    private func badge(_ count: Int) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            center.setBadgeCount(count) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
        }
    }
    @MainActor private func reconcile(
        receipts: [String] = [], unread: Bool = false, changeRegistration: Bool = false
    ) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            PushBadge.reconcile(registration: registration, unread: unread,
                receipts: receipts.map { ["scope": scope, "event": $0] }, scopes: [scope], prefs: prefs, center: center) { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume() }
            }
            // The production callback re-enters the main queue. This change
            // deterministically occurs after capture and before that guard.
            if changeRegistration { prefs.set("new-profile", forKey: "elo.push.registration") }
        }
    }
    @MainActor private func expect(events: Set<String>, badge: Int) async throws {
        var actual: Set<String> = []
        for _ in 0..<50 {
            let notifications = await delivered()
            actual = Set(notifications.compactMap { $0.request.content.userInfo["elo_event"] as? String })
            if actual == events && UIApplication.shared.applicationIconBadgeNumber == badge { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw Failure(description: "Expected \(events.count) delivered events/badge \(badge); got \(actual.count)/\(UIApplication.shared.applicationIconBadgeNumber)")
    }
    @MainActor private func run(_ phase: String) async throws {
        switch phase {
        case "setup":
            print("HARNESS requesting notification and badge permission")
            fflush(stdout)
            let allowed = try await center.requestAuthorization(options: [.alert, .badge])
            print("HARNESS authorization returned \(allowed)")
            fflush(stdout)
            try require(allowed, "Synthetic harness notification permission denied")
            let settings = await center.notificationSettings()
            try require(settings.badgeSetting == .enabled, "Badge permission is not enabled")
            prefs.set(true, forKey: "elo.push.enabled")
            prefs.set(registration, forKey: "elo.push.registration")
            prefs.removeObject(forKey: "elo.push.reads")
            try await badge(0)
            try await expect(events: [], badge: 0)
        case "ack_first":
            try await expect(events: [eventA, eventB], badge: 1)
            try await reconcile(receipts: [eventA])
            try await expect(events: [eventB], badge: 1)
        case "restart_late_push":
            let reads = prefs.dictionary(forKey: "elo.push.reads") as? [String: Double] ?? [:]
            try require(reads[scope + ":" + eventA, default: 0] > Date().timeIntervalSince1970,
                "Read acknowledgement did not survive process restart")
            try await expect(events: [eventA, eventB], badge: 1)
            let inbox = await delivered().map { DeliveredPush(identifier: $0.request.identifier,
                deliveredAt: $0.date.timeIntervalSince1970, data: $0.request.content.userInfo) }
            let pending = PushInbox.pendingMessages(inbox, registration: registration,
                reads: Set(reads.keys), now: Date().timeIntervalSince1970)
            try require(pending.count == 1 && pending[0]["event"] == eventB,
                "Only the unread delivered target should enter native verification")
            try await reconcile()
            try await expect(events: [eventB], badge: 1)
        case "ack_last":
            try await reconcile(receipts: [eventB])
            try await expect(events: [], badge: 0)
        case "local_unread":
            try await reconcile(unread: true)
            try await expect(events: [], badge: 1)
            try await reconcile(unread: false)
            try await expect(events: [], badge: 0)
        case "registration_changes_during_callback":
            try await expect(events: [eventC], badge: 1)
            try await reconcile(receipts: [eventC], changeRegistration: true)
            try await expect(events: [eventC], badge: 1)
            prefs.set(registration, forKey: "elo.push.registration")
            try await reconcile()
            try await expect(events: [], badge: 0)
        default: throw Failure(description: "Unknown phase")
        }
    }
}
