import ObjectiveC
import Darwin
import WebKit
import GoogleUtilities_NSData
import FirebaseCore
import FirebaseMessaging
import Tauri
import UIKit
import UserNotifications

private struct VoipOwnershipArgs: Decodable { let identity: String; let nonce: String }
private struct NativeMediaArgs: Decodable { let payload: String }
private struct CallListenerArgs: Decodable { let channel: Channel }
private struct CallConfigureArgs: Decodable { let enabled: Bool; let registration: String; let endpoint: String; let labels: [String:String]; let ringtone: String? }
private struct CallActionArgs: Decodable { let action: String; let callId: String; let event:String? }
private struct PushRegisterArgs: Decodable { let registration: String }
private struct PushAckArgs: Decodable { let opened: String?; let wake: String? }
private struct PushStatus: Encodable {
    let available: Bool
    let enabled: Bool
    let permission: Bool
    let wake: String?
    let opened: String?
    let token: String?
    let challenge: String?
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
    private var waiting: Invoke?
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
    deinit { observers.forEach(NotificationCenter.default.removeObserver) }

    override func load(webview: WKWebView) {
        DispatchQueue.main.async { [weak self] in
            NativeMedia.shared.webView = webview
            self?.configure()
        }
    }
    @objc func voipOwnership(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(VoipOwnershipArgs.self)
        Task { @MainActor in
            do { invoke.resolve(try await VoipOwnership.proof(identity: args.identity, nonce: args.nonce)) }
            catch { invoke.reject("Could not verify this device for incoming calls. Try again.") }
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

    // Tao 0.35 supplies the delegate methods but does not declare protocol
    // conformance. Firebase refuses to install its APNs callbacks without it.
    // Keep Tao's delegate and lifecycle methods; only supply the missing marker.
    @discardableResult private func configure() -> Bool {
        dispatchPrecondition(condition: .onQueue(.main))
        _ = IncomingCalls.shared
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
        return true
    }

    private func receive(_ data: [AnyHashable: Any], opened: Bool) {
        guard prefs.bool(forKey: "elo.push.enabled"),
              data["elo_registration"] as? String == prefs.string(forKey: "elo.push.registration") else { return }
        if let challenge = data["elo_challenge"] as? String,
           challenge.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil {
            prefs.set(challenge, forKey: "elo.push.challenge")
        } else if data["elo_wake"] as? String == "1", let target = data["elo_target"] as? String,
                  target.count <= 2048, target.range(of: "^[A-Za-z0-9_-]{64,}$", options: .regularExpression) != nil {
            prefs.set(target, forKey: "elo.push.wake")
            if opened { prefs.set(target, forKey: "elo.push.opened") }
        } else { return }
        try? statusChannel?.send([:] as [String: Bool])
    }
    @objc func statusListener(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CallListenerArgs.self)
        DispatchQueue.main.async { self.statusChannel = args.channel; invoke.resolve() }
    }
    @objc func register(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PushRegisterArgs.self)
        guard args.registration.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
            invoke.reject("Invalid notification registration."); return
        }
        // Tauri dispatches commands on its IPC queue. UIKit registration and
        // pending-invoke state must remain on the main queue with FCM callbacks.
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.configure() else {
                invoke.reject("Notifications are not configured."); return
            }
            self.prefs.set(args.registration, forKey: "elo.push.registration")
            self.prefs.removeObject(forKey: "elo.push.challenge")
            self.prefs.set(true, forKey: "elo.push.enabled")
            self.waiting?.reject("Notification setup was restarted.")
            self.waiting = invoke
            Messaging.messaging().isAutoInitEnabled = true
            UIApplication.shared.registerForRemoteNotifications()
            if Messaging.messaging().apnsToken != nil {
                Messaging.messaging().token { [weak self] token, _ in
                    DispatchQueue.main.async {
                        guard let self = self, self.waiting === invoke else { return }
                        if let token = token { self.receivedToken(token) }
                    }
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 25) { [weak self, weak invoke] in
                guard let self = self, let invoke = invoke, self.waiting === invoke else { return }
                self.waiting = nil
                invoke.reject("Could not register notifications. Try again.")
            }
        }
    }
    func messaging(_ messaging: Messaging, didReceiveRegistrationToken fcmToken: String?) {
        DispatchQueue.main.async { [weak self] in
            if let token = fcmToken { self?.receivedToken(token) }
        }
    }
    private func receivedToken(_ token: String) {
        guard prefs.bool(forKey: "elo.push.enabled"),
              Messaging.messaging().apnsToken != nil, !token.isEmpty else { return }
        prefs.set(token, forKey: "elo.push.token")
        waiting?.resolve(["token": token])
        waiting = nil
    }
    @objc func status(_ invoke: Invoke) {
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            guard let self = self else { invoke.reject("Notifications are unavailable."); return }
            invoke.resolve(PushStatus(available: FirebaseApp.app() != nil,
                enabled: self.prefs.bool(forKey: "elo.push.enabled"),
                permission: settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional,
                wake: self.prefs.string(forKey: "elo.push.wake"), opened: self.prefs.string(forKey: "elo.push.opened"),
                token: self.prefs.string(forKey: "elo.push.token"), challenge: self.prefs.string(forKey: "elo.push.challenge")))
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
    @objc func callConfigure(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CallConfigureArgs.self)
        DispatchQueue.main.async { [self] in
            guard args.registration == prefs.string(forKey:"elo.push.registration"),URL(string:args.endpoint)?.scheme == "https" else { invoke.reject("Invalid call registration");return }
            let token = IncomingCalls.shared.configure(enabled:args.enabled,registration:args.registration,endpoint:args.endpoint,labels:args.labels,ringtone:args.ringtone)
            invoke.resolve(["token":token ?? ""])
        }
    }
    @objc func callStatus(_ invoke: Invoke) {
        DispatchQueue.main.async { invoke.resolve(["incoming":IncomingCalls.shared.status() ?? [:]]) }
    }
    @objc func callListener(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CallListenerArgs.self)
        DispatchQueue.main.async { IncomingCalls.shared.answerListener = args.channel; invoke.resolve() }
    }
    @objc func callAction(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CallActionArgs.self)
        DispatchQueue.main.async {
            if args.action == "answer" { invoke.resolve(["handled": IncomingCalls.shared.answerFromApp(args.callId)]); return }
            if args.action == "decline" { invoke.resolve(["handled": IncomingCalls.shared.declineFromApp(args.callId)]); return }
            if args.action == "answering" { IncomingCalls.shared.answering(args.callId) }
            if args.action == "connected" { IncomingCalls.shared.connected(args.callId) }
            if args.action == "ack" { IncomingCalls.shared.acknowledge(args.callId,event:args.event) }
            if args.action == "end" { IncomingCalls.shared.end(args.callId) }
            if args.action == "unlock" { IncomingCalls.shared.requestUnlock(args.callId) }
            invoke.resolve()
        }
    }
    @objc func disable(_ invoke: Invoke) {
        DispatchQueue.main.async { [self] in
            IncomingCalls.shared.disable()
            NativeMedia.shared.stopAll()
            waiting?.reject("Notification setup was cancelled.")
            waiting = nil
            for key in ["enabled", "token", "challenge", "registration", "wake", "opened"] { prefs.removeObject(forKey: "elo.push." + key) }
            let center = UNUserNotificationCenter.current()
            center.getDeliveredNotifications { notifications in
                center.removeDeliveredNotifications(withIdentifiers: notifications.filter {
                    $0.request.content.userInfo["elo_registration"] != nil
                }.map { $0.request.identifier })
            }
            UIApplication.shared.unregisterForRemoteNotifications()
            if FirebaseApp.app() != nil {
                Messaging.messaging().isAutoInitEnabled = false
                Messaging.messaging().deleteToken { _ in invoke.resolve() }
            } else { invoke.resolve() }
        }
    }
}

@_cdecl("init_plugin_elo_push")
func initPluginEloPush() -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(EloPushPlugin()).toOpaque()
}
