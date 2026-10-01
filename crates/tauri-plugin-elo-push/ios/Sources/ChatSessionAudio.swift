import AVFoundation
import UIKit

/// Audio belongs to an explicitly joined chat session, independent of push opt-in.
/// No system incoming-call UI or VoIP wake can activate capture.
@MainActor final class ChatSessionAudio {
    static let shared = ChatSessionAudio()
    private var sessionId: String?

    func set(active: Bool, id: String) throws {
        guard id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
            throw NativePeer.MediaError.invalid
        }
        let audio = AVAudioSession.sharedInstance()
        if active {
            guard sessionId == nil || sessionId == id else { throw NativePeer.MediaError.invalid }
            if sessionId == nil {
                guard UIApplication.shared.applicationState == .active,
                    AVCaptureDevice.authorizationStatus(for: .audio) == .authorized else {
                    throw NativePeer.MediaError.permission
                }
                try audio.setCategory(.playAndRecord, mode: .voiceChat,
                                      options: [.allowBluetoothHFP, .defaultToSpeaker])
                try audio.setActive(true)
                sessionId = id
            }
        } else if sessionId == id {
            sessionId = nil
            // Capture is stopped by the media owner before releasing this session.
            try audio.setActive(false, options: .notifyOthersOnDeactivation)
        }
    }
}
