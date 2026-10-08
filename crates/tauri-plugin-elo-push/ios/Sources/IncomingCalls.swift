import AVFoundation
import CallKit
import Foundation
import PushKit
import Tauri
import UIKit
import WebRTC

/// CallKit owns system presentation and audio activation. The Rust call-only
/// runtime owns admission/signaling; this layer cannot unlock a profile.
@MainActor final class IncomingCalls: NSObject, PKPushRegistryDelegate, CXProviderDelegate {
    static let shared = IncomingCalls()
    private let prefs = UserDefaults.standard
    private let provider: CXProvider
    private let controller = CXCallController()
    private var outgoing = OutgoingCallLedger()
    private var microphoneState: [UUID: Bool] = [:]
    private var muteFeedback: [UUID: (call: UUID, capture: String, revision: UInt64?, muted: Bool, previous: Bool)] = [:]
    private var starts: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var registry: PKPushRegistry?
    private var channel: Channel?
    private var hints: [UUID: IncomingCallHint] = [:]
    private var presentationRevision: UInt64 = 0
    private var answers: [UUID: CXAnswerCallAction] = [:]
    private var events: [[String: Any]] = []
    private var authorized = Set<String>()
    private var captures: [UUID: String] = [:]
    private var connected = Set<UUID>()
    private var ledger: IncomingCallLedger
    private(set) var audioActivated = false
    var systemAudioOwned: Bool { !authorized.isEmpty || outgoing.call != nil }
    var hasRingingPresentation: Bool { hints.keys.contains { !connected.contains($0) && answers[$0] == nil } }

    private override init() {
        let configuration = CXProviderConfiguration()
        configuration.supportsVideo = true
        configuration.maximumCallGroups = 2
        configuration.maximumCallsPerCallGroup = 1
        configuration.supportedHandleTypes = [.generic]
        configuration.includesCallsInRecents = false
        provider = CXProvider(configuration: configuration)
        ledger = IncomingCallLedger(terminal: UserDefaults.standard.dictionary(forKey: "elo.calls.terminal") as? [String: Double] ?? [:])
        super.init()
        provider.setDelegate(self, queue: .main)
    }

    func configure(enabled: Bool) {
        if enabled && registry == nil {
            let value = PKPushRegistry(queue: .main)
            value.delegate = self
            registry = value
            value.desiredPushTypes = [.voIP]
        } else if !enabled {
            registry?.desiredPushTypes = []
            registry = nil
            prefs.removeObject(forKey: "elo.calls.voip-token")
            for id in Array(hints.keys) { finish(id, reason: .remoteEnded) }
            events.removeAll()
        }
    }

    func listen(_ channel: Channel) {
        self.channel = channel
        for event in events { _ = try? channel.send(event) }
    }

    func status() -> [String: Any] {
        ["voipToken": prefs.string(forKey: "elo.calls.voip-token") as Any? ?? NSNull(),
         "apnsSandbox": APNsEnvironment.sandbox,
         "pending": events,
         "presentationRevision": presentationRevision,
         "presentationHints": hints.values.map { $0.event("presentation") },
         "presented": hints.values.map { ["callId": $0.callId, "invitationId": $0.invitationId] }]
    }

    private func presentationChanged() {
        presentationRevision += 1
        // A refresh signal only. Rust verifies the current snapshot locally;
        // this event is neither a call admission nor an authorization to capture.
        _ = try? channel?.send(["action": "presentation", "eventId": UUID().uuidString])
    }

    private func emit(_ event: [String: Any]) {
        var value = event
        value["eventId"] = UUID().uuidString
        // Never retain profile data or an unlimited notification queue.
        if events.count == 32 { events.removeFirst() }
        events.append(value)
        _ = try? channel?.send(value)
    }

    func pushRegistry(_ registry: PKPushRegistry, didUpdate pushCredentials: PKPushCredentials, for type: PKPushType) {
        guard type == .voIP else { return }
        prefs.set(pushCredentials.token.map { String(format: "%02x", $0) }.joined(), forKey: "elo.calls.voip-token")
        emit(["action": "token"])
    }

    func pushRegistry(_ registry: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) {
        guard type == .voIP else { return }
        prefs.removeObject(forKey: "elo.calls.voip-token")
        emit(["action": "token"])
    }

    func pushRegistry(_ registry: PKPushRegistry, didReceiveIncomingPushWith payload: PKPushPayload, for type: PKPushType, completion: @escaping () -> Void) {
        guard type == .voIP else { completion(); return }
        report(payload.dictionaryPayload, completion: completion)
    }

    func report(_ data: [AnyHashable: Any], completion: @escaping () -> Void) {
        ForegroundRingtone.shared.pausePlayback()
        let now = Date().timeIntervalSince1970
        let hint = IncomingCallHint(data, now: now)
        let valid = hint.map {
            prefs.bool(forKey: "elo.push.enabled") && PushRegistrations.contains($0.registration, prefs: prefs)
                && !ledger.contains($0.invitationId, now: now)
        } ?? false
        // Every VoIP delivery is reported promptly, including an expired or
        // invalid hint. Invalid attempts end immediately and never reach media.
        let id = hint?.uuid ?? UUID()
        let update = CXCallUpdate()
        update.remoteHandle = CXHandle(type: .generic, value: "elo.now")
        update.localizedCallerName = "elo.now"
        update.hasVideo = false
        update.supportsHolding = false
        update.supportsGrouping = false
        update.supportsUngrouping = false
        update.supportsDTMF = false
        let duplicate = hints[id] != nil
        if valid, let hint, !duplicate { hints[id] = hint; presentationChanged() }
        provider.reportNewIncomingCall(with: id, update: update) { [weak self] error in
            Task { @MainActor in
                defer { completion() }
                guard let self else { return }
                if duplicate { return }
                guard valid, let hint, error == nil else {
                    if self.hints.removeValue(forKey: id) != nil { self.presentationChanged() }
                    if error == nil { self.provider.reportCall(with: id, endedAt: Date(), reason: .failed) }
                    return
                }
                // The user may have ended the call before CallKit's asynchronous
                // report completion. A late success must not restart admission.
                guard self.hints[id] == hint else { return }
                self.emit(hint.event("incoming"))
                DispatchQueue.main.asyncAfter(deadline: .now() + max(0, hint.expires - now)) { [weak self] in
                    guard let self, self.hints[id] != nil, !self.connected.contains(id), self.answers[id] == nil else { return }
                    self.finish(id, reason: .unanswered)
                }
            }
        }
    }

    func permitsBackgroundAudio(_ callId: String) -> Bool {
        authorized.contains(callId) || (outgoing.call?.callId == callId && outgoing.call?.started == true)
    }

    func startOutgoing(_ request: [String: Any]) async throws {
        guard let value = OutgoingSystemCall(request) else { throw NativePeer.MediaError.invalid }
        if let existing = outgoing.call {
            guard existing.matches(value), existing.started else { throw NativePeer.MediaError.ended }
            return
        }
        // Permission is requested by the foreground call flow. CallKit callbacks
        // never prompt behind the lock screen or resurrect an unverified call.
        guard UIApplication.shared.applicationState == .active,
              AVCaptureDevice.authorizationStatus(for: .audio) == .authorized,
              hints[value.id] == nil, ChatSessionAudio.shared.manageWithSystem(value),
              outgoing.register(value) else { throw NativePeer.MediaError.permission }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            starts[value.id] = continuation
            let action = CXStartCallAction(call: value.id, handle: CXHandle(type: .generic, value: value.name))
            action.isVideo = false
            controller.request(CXTransaction(action: action)) { [weak self] error in
                guard error != nil else { return }
                Task { @MainActor in self?.finishOutgoing(value.id, reason: .failed, notify: true) }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                guard let self, self.starts[value.id] != nil else { return }
                self.finishOutgoing(value.id, reason: .failed, notify: true)
            }
        }
    }

    func outgoingConnected(_ id: UUID) throws {
        guard outgoing.call?.id == id, outgoing.call?.started == true else { throw NativePeer.MediaError.ended }
        if outgoing.connect(id) { provider.reportOutgoingCall(with: id, connectedAt: Date()) }
    }

    func outgoingEnded(_ id: UUID) {
        finishOutgoing(id, reason: .remoteEnded, notify: false)
    }

    /// Reflect a signed in-app microphone change in system controls without
    /// treating our own transaction as another user intent or signing it twice.
    func reconcileMute(capture: String, muted: Bool) {
        let id = outgoing.call?.captureId == capture ? outgoing.call?.id
            : captures.first(where: { $0.value == capture })?.key
        guard let id, outgoing.call?.id == id || hints[id] != nil,
              (microphoneState[id] ?? false) != muted, muteFeedback.count < 8 else { return }
        let action = CXSetMutedCallAction(call: id, muted: muted)
        let feedback = (call: id, capture: capture,
            revision: NativeMedia.shared.systemMuteRevision(id: capture),
            muted: muted, previous: microphoneState[id] ?? false)
        muteFeedback[action.uuid] = feedback
        microphoneState[id] = muted
        controller.request(CXTransaction(action: action)) { [weak self] error in
            guard error != nil else { return }
            Task { @MainActor in
                guard let self, let pending = self.muteFeedback.removeValue(forKey: action.uuid),
                      NativeMedia.shared.systemMuteRevision(id: pending.capture) == pending.revision else { return }
                self.microphoneState[pending.call] = pending.previous
            }
        }
    }

    private func forgetMute(_ id: UUID) {
        microphoneState.removeValue(forKey: id)
        muteFeedback = muteFeedback.filter { $0.value.call != id }
    }

    private func finishOutgoing(_ id: UUID, reason: CXCallEndedReason, notify: Bool) {
        guard let call = outgoing.remove(id) else { return }
        forgetMute(id)
        starts.removeValue(forKey: id)?.resume(throwing: NativePeer.MediaError.ended)
        // The capture UUID is exact: a delayed callback cannot stop its successor.
        NativeMedia.shared.stop(id: call.captureId)
        if notify { ChatSessionAudio.shared.systemEvent(call, action: "end") }
        provider.reportCall(with: id, endedAt: Date(), reason: reason)
    }

    func provider(_ provider: CXProvider, perform action: CXStartCallAction) {
        guard let call = outgoing.call, call.id == action.callUUID,
              outgoing.start(action.callUUID) else { action.fail(); return }
        let update = CXCallUpdate()
        update.remoteHandle = CXHandle(type: .generic, value: call.name)
        update.localizedCallerName = call.name
        update.hasVideo = false
        update.supportsHolding = false
        update.supportsGrouping = false
        update.supportsUngrouping = false
        update.supportsDTMF = false
        provider.reportCall(with: action.callUUID, updated: update)
        provider.reportOutgoingCall(with: action.callUUID, startedConnectingAt: Date())
        action.fulfill()
        starts.removeValue(forKey: action.callUUID)?.resume()
    }

    func command(_ request: [String: Any]) throws -> [String: Any] {
        if request["op"] as? String == "ack", let id = request["eventId"] as? String {
            events.removeAll { $0["eventId"] as? String == id }
            return [:]
        }
        if request["op"] as? String == "status" { return status() }
        guard let callId = request["callId"] as? String,
              let invitationId = request["invitationId"] as? String,
              let (id, hint) = hints.first(where: { $0.value.callId == callId && $0.value.invitationId == invitationId }) else {
            if request["op"] as? String == "ended" { return [:] }
            throw NativePeer.MediaError.ended
        }
        switch request["op"] as? String {
        case "authorize":
            guard answers[id] != nil, let capture = request["mediaId"] as? String,
                  UUID(uuidString: capture) != nil else { throw NativePeer.MediaError.invalid }
            authorized.insert(callId)
            captures[id] = capture
        case "connected":
            guard authorized.contains(callId), let action = answers.removeValue(forKey: id) else { throw NativePeer.MediaError.invalid }
            connected.insert(id)
            action.fulfill()
        case "answer_failed": finish(id, reason: .failed)
        case "ended":
            let reason: CXCallEndedReason = request["reason"] as? String == "answered_elsewhere" ? .answeredElsewhere : .remoteEnded
            finish(id, reason: reason)
        case "update":
            // Labels are supplied only after native verification, never from APNs.
            let update = CXCallUpdate()
            update.localizedCallerName = String((request["name"] as? String ?? "elo.now").prefix(120))
            update.hasVideo = request["video"] as? Bool == true
            provider.reportCall(with: id, updated: update)
        default: throw NativePeer.MediaError.invalid
        }
        _ = hint
        return [:]
    }

    private func finish(_ id: UUID, reason: CXCallEndedReason) {
        guard let hint = hints.removeValue(forKey: id) else { return }
        presentationChanged()
        forgetMute(id)
        if let capture = captures.removeValue(forKey: id) { NativeMedia.shared.stop(id: capture) }
        answers.removeValue(forKey: id)?.fail()
        connected.remove(id)
        authorized.remove(hint.callId)
        ledger.finish(hint, now: Date().timeIntervalSince1970)
        prefs.set(ledger.terminal, forKey: "elo.calls.terminal")
        provider.reportCall(with: id, endedAt: Date(), reason: reason)
        emit(hint.event("ended"))
    }

    func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        guard let hint = hints[action.callUUID], hint.expires > Date().timeIntervalSince1970,
              answers[action.callUUID] == nil else { action.fail(); return }
        answers[action.callUUID] = action
        emit(hint.event("answer"))
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, self.answers[action.callUUID] != nil else { return }
            self.finish(action.callUUID, reason: .failed)
        }
    }

    func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        if outgoing.call?.id == action.callUUID {
            finishOutgoing(action.callUUID, reason: .remoteEnded, notify: true)
            action.fulfill()
            return
        }
        guard let hint = hints[action.callUUID] else { action.fulfill(); return }
        emit(hint.event(connected.contains(action.callUUID) || answers[action.callUUID] != nil ? "end" : "decline"))
        // Stop capture synchronously; the signed network close may complete later.
        finish(action.callUUID, reason: .remoteEnded)
        action.fulfill()
    }

    func provider(_ provider: CXProvider, perform action: CXSetMutedCallAction) {
        if let feedback = muteFeedback.removeValue(forKey: action.uuid) {
            guard feedback.call == action.callUUID, feedback.muted == action.isMuted,
                  outgoing.call?.id == action.callUUID || hints[action.callUUID] != nil,
                  NativeMedia.shared.systemMuteRevision(id: feedback.capture) == feedback.revision else { action.fail(); return }
            microphoneState[action.callUUID] = action.isMuted
            action.fulfill()
            return
        }
        if let call = outgoing.call, call.id == action.callUUID, call.started {
            microphoneState[action.callUUID] = action.isMuted
            let revision = NativeMedia.shared.beginSystemMute(id: call.captureId)
            ChatSessionAudio.shared.systemEvent(call, action: "mute", muted: action.isMuted, systemMuteRevision: revision)
            action.fulfill()
            return
        }
        guard let hint = hints[action.callUUID], authorized.contains(hint.callId) else { action.fail(); return }
        guard let capture = captures[action.callUUID] else { action.fail(); return }
        microphoneState[action.callUUID] = action.isMuted
        let revision = NativeMedia.shared.beginSystemMute(id: capture)
        var event = hint.event("mute"); event["muted"] = action.isMuted
        event["systemMuteRevision"] = revision
        emit(event); action.fulfill()
    }

    func provider(_ provider: CXProvider, timedOutPerforming action: CXAction) {
        guard let action = action as? CXCallAction else { return }
        finishOutgoing(action.callUUID, reason: .failed, notify: true)
        finish(action.callUUID, reason: .failed)
    }

    func providerDidReset(_ provider: CXProvider) {
        if let call = outgoing.call { finishOutgoing(call.id, reason: .failed, notify: true) }
        NativeMedia.shared.stopAll()
        for id in Array(hints.keys) { finish(id, reason: .failed) }
        audioActivated = false
    }

    func provider(_ provider: CXProvider, didActivate audioSession: AVAudioSession) {
        audioActivated = true
        let rtc = RTCAudioSession.sharedInstance()
        rtc.audioSessionDidActivate(audioSession)
        rtc.isAudioEnabled = true
        NativeMedia.shared.systemAudioActivated()
    }

    func provider(_ provider: CXProvider, didDeactivate audioSession: AVAudioSession) {
        audioActivated = false
        let rtc = RTCAudioSession.sharedInstance()
        rtc.isAudioEnabled = false
        rtc.audioSessionDidDeactivate(audioSession)
        NativeMedia.shared.systemAudioDeactivated()
    }
}
