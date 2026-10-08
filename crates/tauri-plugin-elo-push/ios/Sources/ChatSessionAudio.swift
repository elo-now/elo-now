import AVFoundation
import UIKit

/// Audio belongs to an explicitly joined chat session, independent of push opt-in.
/// Incoming audio is admitted separately by the call-only native runtime.
@MainActor final class ChatSessionAudio {
    static let shared = ChatSessionAudio()
    private var sessionId: String?
    private var activation: String?
    private var systemManaged = false
    var active: Bool { sessionId != nil }
    private var observer: NSObjectProtocol?
    private var changed: (() -> Void)?
    private var systemAction: (([String: Any]) -> Void)?
    private(set) var categoryOptions: AVAudioSession.CategoryOptions = [.allowBluetoothHFP, .defaultToSpeaker]

    private init() {
        observer = NotificationCenter.default.addObserver(
            forName: AVAudioSession.routeChangeNotification, object: nil, queue: .main
        ) { [weak self] notification in
            let reason = (notification.userInfo?[AVAudioSessionRouteChangeReasonKey] as? NSNumber)?.uintValue
            Task { @MainActor [weak self] in self?.routeChanged(reason: reason) }
        }
    }

    func set(active: Bool, id: String, activation: String, changed: (() -> Void)? = nil, systemAction: (([String: Any]) -> Void)? = nil) throws {
        guard id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
            throw NativePeer.MediaError.invalid
        }
        let audio = AVAudioSession.sharedInstance()
        if active {
            guard sessionId == nil || (sessionId == id && self.activation == activation) else { throw NativePeer.MediaError.invalid }
            if sessionId == nil {
                ForegroundRingtone.shared.stop()
                guard (UIApplication.shared.applicationState == .active || IncomingCalls.shared.permitsBackgroundAudio(id)),
                    AVCaptureDevice.authorizationStatus(for: .audio) == .authorized else {
                    throw NativePeer.MediaError.permission
                }
                categoryOptions = [.allowBluetoothHFP, .defaultToSpeaker]
                try audio.setCategory(.playAndRecord, mode: .voiceChat, options: categoryOptions)
                if !IncomingCalls.shared.permitsBackgroundAudio(id) { try audio.setActive(true) }
                systemManaged = IncomingCalls.shared.permitsBackgroundAudio(id)
                sessionId = id
                self.activation = activation
            }
            self.changed = changed
            self.systemAction = systemAction
        } else if sessionId == id && self.activation == activation {
            sessionId = nil
            self.activation = nil
            self.changed = nil
            self.systemAction = nil
            // Capture is stopped by the media owner before releasing this session.
            try? audio.overrideOutputAudioPort(.none)
            try? audio.setPreferredInput(nil)
            if !systemManaged && !IncomingCalls.shared.systemAudioOwned { try audio.setActive(false, options: .notifyOthersOnDeactivation) }
            systemManaged = false
        }
    }

    func manageWithSystem(_ call: OutgoingSystemCall) -> Bool {
        guard sessionId == call.callId, activation == call.activation, systemAction != nil else { return false }
        systemManaged = true
        return true
    }

    func systemEvent(_ call: OutgoingSystemCall, action: String, muted: Bool? = nil, systemMuteRevision: UInt64? = nil) {
        guard sessionId == call.callId, activation == call.activation else { return }
        var event = call.event(action, muted: muted)
        if let systemMuteRevision { event["systemMuteRevision"] = systemMuteRevision }
        systemAction?(event)
    }

    private func externalKind(_ port: AVAudioSession.Port) -> String? {
        switch port {
        case .bluetoothHFP, .bluetoothA2DP, .bluetoothLE: return "bluetooth"
        case .headphones, .headsetMic, .usbAudio: return "headphones"
        default: return nil
        }
    }

    private func routeChanged(reason: UInt?) {
        guard sessionId != nil else { return }
        let audio = AVAudioSession.sharedInstance()
        if reason == AVAudioSession.RouteChangeReason.newDeviceAvailable.rawValue,
            (audio.availableInputs ?? []).contains(where: { externalKind($0.portType) != nil }) {
            // A newly connected headset wins over a previous explicit built-in
            // selection. Do not continually reapply a route on camera updates.
            try? audio.overrideOutputAudioPort(.none)
            try? audio.setPreferredInput(nil)
        }
        changed?()
    }

    func route(id: String, activation: String, outputId: String?) throws -> [String: Any] {
        guard sessionId == id && self.activation == activation else { throw NativePeer.MediaError.ended }
        let audio = AVAudioSession.sharedInstance()
        let inputs = audio.availableInputs ?? []
        let hasReceiver = UIDevice.current.userInterfaceIdiom == .phone && inputs.contains { $0.portType == .builtInMic }
        let external = inputs.filter { externalKind($0.portType) != nil }
        if let outputId {
            let input = external.first { "input:" + $0.uid == outputId }
            guard outputId == "system" || outputId == "speaker" || (outputId == "receiver" && hasReceiver) || input != nil else {
                throw NativePeer.MediaError.invalid
            }
            // Speaker is a transient override, not a permanent default that
            // would steal audio from a headset connected later in the session.
            categoryOptions = outputId == "system" ? [.allowBluetoothHFP, .defaultToSpeaker] : [.allowBluetoothHFP]
            try audio.setCategory(.playAndRecord, mode: .voiceChat, options: categoryOptions)
            if outputId == "speaker" {
                try audio.setPreferredInput(nil)
                try audio.overrideOutputAudioPort(.speaker)
            } else {
                try audio.overrideOutputAudioPort(.none)
                let preferred = outputId == "receiver" ? inputs.first { $0.portType == .builtInMic } : input
                try audio.setPreferredInput(preferred)
            }
        }
        var outputs: [[String: Any]] = [["id": "speaker", "kind": "speaker"]]
        if hasReceiver { outputs.insert(["id": "receiver", "kind": "receiver"], at: 0) }
        for input in external {
            outputs.append(["id": "input:" + input.uid, "kind": externalKind(input.portType)!, "name": String(input.portName.prefix(120))])
        }
        outputs.append(["id": "system", "kind": "system"])
        var selected: String?
        if let output = audio.currentRoute.outputs.first {
            switch output.portType {
            case .builtInSpeaker: selected = "speaker"
            case .builtInReceiver: selected = hasReceiver ? "receiver" : "system"
            default:
                if let input = audio.currentRoute.inputs.first(where: { current in external.contains { $0.uid == current.uid } }) {
                    selected = "input:" + input.uid
                } else {
                    // Output-only routes are chosen by iOS; do not pretend they
                    // are independently selectable through setPreferredInput.
                    selected = "system"
                    if let kind = externalKind(output.portType) {
                        outputs[outputs.count - 1] = ["id": "system", "kind": kind, "name": String(output.portName.prefix(120))]
                    }
                }
            }
        }
        return ["selected": selected as Any? ?? NSNull(), "outputs": outputs]
    }
}
