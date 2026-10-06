import ObjectiveC
import Darwin
import WebKit
import GoogleUtilities_NSData
import FirebaseCore
import FirebaseMessaging
import FirebaseInstallations
import Tauri
import UIKit
import UserNotifications

private struct NativeMediaArgs: Decodable { let payload: String }
private struct CallStateArgs: Decodable { let active: Bool; let sessionId: String; let activation: String; let camera: Bool; let routeChannel: Channel? }
private struct CallAudioArgs: Decodable { let sessionId: String; let activation: String; let outputId: String? }
private struct PushRegisterArgs: Decodable { let registration: String; let background: Bool? }
private struct PushStatusArgs: Decodable { let registration: String? }
private struct PushAckArgs: Decodable { let opened: String?; let wake: String? }
private struct PushStatusListenerArgs: Decodable { let channel: Channel }
private struct IncomingCallArgs: Decodable { let payload: String }
private struct PushReconcileArgs: Decodable {
    let registration: String
    let unread: Bool
    let receipts: [[String:String]]
    let scopes: [String]
}
private struct PushStatus: Encodable {
    let available: Bool
    let enabled: Bool
    let permission: Bool
    let registration: String?
    let wake: String?
    let opened: String?
    let token: String?
    let challenge: String?
    let delivered: [[String: String]]
}

final class EloPushPlugin: Plugin, MessagingDelegate {
    @objc func deviceModel(_ invoke: Invoke) {
        var hardware = utsname()
        uname(&hardware)
        let identifier = Mirror(reflecting: hardware.machine).children.reduce(into: "") { result, item in
            guard let byte = item.value as? Int8, byte != 0 else { return }
            result.append(Character(UnicodeScalar(UInt8(bitPattern: byte))))
        }
        let model = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? identifier
        invoke.resolve(["model": model, "fallback": UIDevice.current.model])
    }

    private let prefs = UserDefaults.standard
    private var registrationOperation: Task<Void, Never>?
    private var waiting: Invoke?
    private var registrationAttempt: UUID?
    private var observers: [NSObjectProtocol] = []
    private var statusChannel: Channel?

    override init() {
        super.init()
        DispatchQueue.main.async { [weak self] in self?.configure() }
        for name in ["elo.push.received", "elo.push.opened"] {
            observers.append(NotificationCenter.default.addObserver(forName: NSNotification.Name(name), object: nil, queue: .main) { [weak self] event in
                self?.receive(event.userInfo ?? [:], opened: name == "elo.push.opened")
            })
        }
    }

    @objc func incomingListener(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushStatusListenerArgs.self)
        Task { @MainActor in IncomingCalls.shared.listen(args.channel); invoke.resolve() }
    }
    @objc func incomingStatus(_ invoke: Invoke) {
        Task { @MainActor in invoke.resolve(IncomingCalls.shared.status()) }
    }
    @objc func callBindings(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(IncomingCallArgs.self)
        guard args.payload.utf8.count <= 3 * 1024 * 1024,
              let body = try JSONSerialization.jsonObject(with: Data(args.payload.utf8)) as? [String: Any] else {
            invoke.reject("invalid"); return
        }
        do { invoke.resolve(try CallBindings.command(body)) }
        catch { invoke.reject("unavailable") }
    }
    @objc func incomingCall(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(IncomingCallArgs.self)
        guard args.payload.utf8.count <= 32768,
              let body = try JSONSerialization.jsonObject(with: Data(args.payload.utf8)) as? [String: Any] else {
            invoke.reject("invalid"); return
        }
        Task { @MainActor in
            do { invoke.resolve(try IncomingCalls.shared.command(body)) }
            catch { invoke.reject("unavailable") }
        }
    }
    deinit { observers.forEach(NotificationCenter.default.removeObserver) }

    override func load(webview: WKWebView) {
        DispatchQueue.main.async { [weak self] in
            NativeMedia.shared.webView = webview
            self?.configure()
        }
    }
    @objc func nativeMedia(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(NativeMediaArgs.self)
        guard args.payload.utf8.count <= 196608,
            let value = try JSONSerialization.jsonObject(with: Data(args.payload.utf8)) as? [String: Any] else {
            invoke.reject("invalid"); return
        }
        Task { @MainActor in
            do { invoke.resolve(try await NativeMedia.shared.command(value)) }
            catch NativePeer.MediaError.permission { invoke.resolve(["error": "NotAllowedError"]) }
            catch NativePeer.MediaError.ended { invoke.resolve(["error": "ended"]) }
            catch { invoke.resolve(["error": "unavailable"]) }
        }
    }

    @objc func setCallState(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CallStateArgs.self)
        Task { @MainActor in
            do {
                try ChatSessionAudio.shared.set(active: args.active, id: args.sessionId, activation: args.activation, changed: {
                    _ = try? args.routeChannel?.send(["sessionId": args.sessionId, "activation": args.activation])
                }, systemAction: { event in
                    _ = try? args.routeChannel?.send(event)
                })
                invoke.resolve()
            } catch { invoke.reject("unavailable") }
        }
    }

    @objc func callAudio(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CallAudioArgs.self)
        Task { @MainActor in
            do { invoke.resolve(try ChatSessionAudio.shared.route(id: args.sessionId, activation: args.activation, outputId: args.outputId)) }
            catch { invoke.reject("unavailable") }
        }
    }

    // Tao 0.35 supplies the delegate methods but does not declare protocol
    // conformance. Firebase refuses to install its APNs callbacks without it.
    // Keep Tao's delegate and lifecycle methods; only supply the missing marker.
    @MainActor @discardableResult private func configure() -> Bool {
        dispatchPrecondition(condition: .onQueue(.main))
        // Anchor the gzip category used by Firebase heartbeat headers. A global
        // -ObjC flag loads duplicate Tauri/SwiftRs objects from plugin archives.
        // Referencing this exported constant retains just its category object.
        guard !GULNSDataZlibErrorDomain.isEmpty else { return false }
        guard let delegate = UIApplication.shared.delegate,
              let delegateClass = object_getClass(delegate),
              let delegateProtocol = objc_getProtocol("UIApplicationDelegate") else { return false }
        if !class_conformsToProtocol(delegateClass, delegateProtocol) {
            class_addProtocol(delegateClass, delegateProtocol)
        }
        if FirebaseApp.app() == nil,
           Bundle.main.path(forResource: "GoogleService-Info", ofType: "plist") != nil {
            FirebaseApp.configure()
        }
        guard FirebaseApp.app() != nil else { return false }
        Messaging.messaging().delegate = self
        Messaging.messaging().isAutoInitEnabled = prefs.bool(forKey: "elo.push.enabled")
        if prefs.bool(forKey: "elo.push.enabled") {
            UIApplication.shared.registerForRemoteNotifications()
        }
        IncomingCalls.shared.configure(enabled: prefs.bool(forKey: "elo.push.enabled"))
        return true
    }

    private func receive(_ data: [AnyHashable: Any], opened: Bool) {
        guard prefs.bool(forKey: "elo.push.enabled"),
              let registration = data["elo_registration"] as? String,
              PushRegistrations.contains(registration, prefs: prefs) else { return }
        if let challenge = data["elo_challenge"] as? String,
           challenge.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil {
            prefs.set(challenge, forKey: PushRegistrations.challengeKey(registration))
        } else if data["elo_wake"] as? String == "1", let target = data["elo_target"] as? String,
                  target.count <= 2048, target.range(of: "^[A-Za-z0-9_-]{64,}$", options: .regularExpression) != nil {
            if data["elo_category"] as? String == "session_start",
               PushInbox.isExpired(DeliveredPush(identifier: "", deliveredAt: Date().timeIntervalSince1970, data: data),
                   now: Date().timeIntervalSince1970) { return }
            prefs.set(target, forKey: "elo.push.wake")
            prefs.set(registration, forKey: "elo.push.wake.registration")
            if opened {
                prefs.set(target, forKey: "elo.push.opened")
                prefs.set(registration, forKey: "elo.push.opened.registration")
            }
        } else { return }
        try? statusChannel?.send([:] as [String: Bool])
    }
    @objc func statusListener(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushStatusListenerArgs.self)
        DispatchQueue.main.async { self.statusChannel = args.channel; invoke.resolve() }
    }
    @objc func register(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushRegisterArgs.self)
        guard args.registration.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
            invoke.reject("Invalid notification registration."); return
        }
        // Tauri dispatches commands on its IPC queue. UIKit registration and
        // pending-invoke state must remain on the main queue with FCM callbacks.
        DispatchQueue.main.async { [weak self, invoke] in
            guard let self = self, self.configure() else {
                invoke.reject("Notifications are not configured."); return
            }
            PushBadge.invalidate(prefs: self.prefs)
            guard PushRegistrations.add(args.registration, prefs: self.prefs) else {
                invoke.reject("Too many notification registrations."); return
            }
            // One Firebase installation delivers every hosting route. Adding a
            // route must not restart provider registration or discard challenges.
            if self.prefs.bool(forKey: "elo.push.enabled"),
               let token = self.prefs.string(forKey: "elo.push.installation-id"), !token.isEmpty {
                invoke.resolve(["token": token]); return
            }
            self.prefs.set(true, forKey: "elo.push.enabled")
            IncomingCalls.shared.configure(enabled: true)
            self.waiting?.reject("Notification setup was restarted.")
            let attempt = UUID()
            self.registrationAttempt = attempt
            self.waiting = args.background == true ? nil : invoke
            Messaging.messaging().isAutoInitEnabled = true
            UIApplication.shared.registerForRemoteNotifications()
            let previous = self.registrationOperation
            self.registrationOperation = Task { @MainActor [weak self] in
                await previous?.value
                guard let self = self, self.registrationAttempt == attempt else { return }
                do {
                    // APNs registration is asynchronous. Do not register an FID
                    // before Firebase can bind it to this installation's APNs token.
                    while Messaging.messaging().apnsToken == nil {
                        guard self.registrationAttempt == attempt else { return }
                        try await Task.sleep(nanoseconds: 100_000_000)
                    }
                    try await Messaging.messaging().register()
                    let installationId = try await Installations.installations().installationID()
                    guard self.registrationAttempt == attempt, self.prefs.bool(forKey: "elo.push.enabled") else { return }
                    self.receivedRegistration(installationId)
                    self.registrationAttempt = nil
                    self.waiting?.resolve(["token": installationId])
                    self.waiting = nil
                } catch {
                    guard self.registrationAttempt == attempt else { return }
                    self.registrationAttempt = nil
                    self.waiting?.reject("Could not register notifications. Try again.")
                    self.waiting = nil
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 25) { [weak self] in
                guard let self = self, self.registrationAttempt == attempt else { return }
                self.registrationAttempt = nil
                self.waiting?.reject("Could not register notifications. Try again.")
                self.waiting = nil
            }
            // Resolve after arming the attempt, so logout can cancel it before delivery resumes.
            if args.background == true { invoke.resolve() }
        }
    }
    func messaging(_ messaging: Messaging, didReceiveRegistration installationId: String?) {
        DispatchQueue.main.async { [weak self] in
            if let installationId = installationId { self?.receivedRegistration(installationId) }
        }
    }
    private func receivedRegistration(_ installationId: String) {
        guard prefs.bool(forKey: "elo.push.enabled"),
              Messaging.messaging().apnsToken != nil, !installationId.isEmpty else { return }
        prefs.set(installationId, forKey: "elo.push.installation-id")
        prefs.removeObject(forKey: "elo.push.token")
        try? statusChannel?.send([:] as [String: Bool])
    }
    @objc func status(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushStatusArgs.self)
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { [weak self] settings in
            center.getDeliveredNotifications { notifications in
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { invoke.reject("Notifications are unavailable."); return }
                    let enabled = self.prefs.bool(forKey: "elo.push.enabled")
                    let registration = args.registration.flatMap { PushRegistrations.contains($0, prefs: self.prefs) ? $0 : nil }
                    let now = Date().timeIntervalSince1970
                    let reads = self.prefs.dictionary(forKey: "elo.push.reads") as? [String: Double] ?? [:]
                    let delivered = enabled ? PushInbox.pendingMessages(
                        Self.inbox(notifications), registration: registration ?? "",
                        reads: Set(reads.filter { $0.value > now }.keys), now: now
                    ) : []
                    invoke.resolve(PushStatus(available: FirebaseApp.app() != nil,
                        enabled: enabled,
                        permission: settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional,
                        registration: registration,
                        wake: args.registration == nil || registration != nil && PushRegistrations.targetRegistration("wake", prefs: self.prefs) == registration ? self.prefs.string(forKey: "elo.push.wake") : nil,
                        opened: args.registration == nil || registration != nil && PushRegistrations.targetRegistration("opened", prefs: self.prefs) == registration ? self.prefs.string(forKey: "elo.push.opened") : nil,
                        token: self.prefs.string(forKey: "elo.push.installation-id"), challenge: registration.flatMap { self.prefs.string(forKey: PushRegistrations.challengeKey($0)) },
                        delivered: delivered))
                }
            }
        }
    }
    private static func inbox(_ notifications: [UNNotification]) -> [DeliveredPush] {
        notifications.map { DeliveredPush(identifier: $0.request.identifier,
            deliveredAt: $0.date.timeIntervalSince1970, data: $0.request.content.userInfo) }
    }
    @objc func reconcile(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushReconcileArgs.self)
        DispatchQueue.main.async { [self] in
            PushBadge.reconcile(registration: args.registration, unread: args.unread,
                receipts: args.receipts, scopes: args.scopes, prefs: prefs) { error in
                if error != nil { invoke.reject("Could not update notification badge.") }
                else { invoke.resolve() }
            }
        }
    }
    @objc func ack(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushAckArgs.self)
        for (key, value) in [("opened", args.opened), ("wake", args.wake)] {
            if let value = value, prefs.string(forKey: "elo.push." + key) == value {
                prefs.removeObject(forKey: "elo.push." + key)
            }
        }
        invoke.resolve()
    }
    @objc func remove(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushRegisterArgs.self)
        DispatchQueue.main.async { [self] in
            PushBadge.invalidate(prefs: prefs)
            PushRegistrations.remove(args.registration, prefs: prefs)
            if PushRegistrations.all(prefs).isEmpty { IncomingCalls.shared.configure(enabled: false) }
            let center = UNUserNotificationCenter.current()
            if PushRegistrations.all(prefs).isEmpty { center.setBadgeCount(0) { _ in } }
            center.getDeliveredNotifications { notifications in
                center.removeDeliveredNotifications(withIdentifiers: notifications.filter {
                    $0.request.content.userInfo["elo_registration"] as? String == args.registration
                }.map { $0.request.identifier })
                invoke.resolve()
            }
        }
    }
    @objc func disable(_ invoke: Invoke) {
        DispatchQueue.main.async { [self] in
            PushBadge.invalidate(prefs: prefs)
            waiting?.reject("Notification setup was cancelled.")
            waiting = nil
            registrationAttempt = nil
            IncomingCalls.shared.configure(enabled: false)
            for key in prefs.dictionaryRepresentation().keys where key.hasPrefix("elo.push.") {
                prefs.removeObject(forKey: key)
            }
            let center = UNUserNotificationCenter.current()
            center.setBadgeCount(0) { _ in }
            center.getDeliveredNotifications { notifications in
                center.removeDeliveredNotifications(withIdentifiers: notifications.filter {
                    $0.request.content.userInfo["elo_registration"] != nil
                }.map { $0.request.identifier })
            }
            UIApplication.shared.unregisterForRemoteNotifications()
            if FirebaseApp.app() != nil {
                Messaging.messaging().isAutoInitEnabled = false
                let previous = registrationOperation
                registrationOperation = Task { @MainActor in
                    await previous?.value
                    try? await Messaging.messaging().unregister()
                }
            }
            // Rust can revoke its route immediately, even while Firebase is offline.
            invoke.resolve()
        }
    }
}

@_cdecl("init_plugin_elo_push")
func initPluginEloPush() -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(EloPushPlugin()).toOpaque()
}
