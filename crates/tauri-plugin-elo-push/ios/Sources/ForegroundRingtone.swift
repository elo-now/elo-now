import AVFoundation
import UIKit

/// An in-app alert, separate from CallKit. Ambient playback respects Silent mode;
/// iOS does not expose a general Focus/DND state to apps. Never use critical alerts.
@MainActor final class ForegroundRingtone {
    static let shared = ForegroundRingtone()
    private var state = ForegroundRingtoneState()
    private var player: AVAudioPlayer?
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var waiting = false
    private var ownsAmbientSession = false
    private var changedCategory = false
    private var previousCategory: (AVAudioSession.Category, AVAudioSession.Mode, AVAudioSession.CategoryOptions)?

    private init() {
        for name in [UIApplication.willResignActiveNotification, UIApplication.didEnterBackgroundNotification,
                     UIApplication.protectedDataWillBecomeUnavailableNotification, AVAudioSession.interruptionNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.stop() }
            })
        }
    }

    func update(epoch: UInt64, token: String, revision: Int64, enabled: Bool, expires: Double) {
        guard state.admit(epoch: epoch) else { return }
        let previous = state.token
        state.update(token: token, revision: revision, enabled: enabled, expires: expires, now: Date().timeIntervalSince1970 * 1_000)
        if state.token != previous { releasePlayer() }
        tick()
        if state.token != nil && timer == nil {
            timer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.tick() }
            }
        }
    }

    private func tick() {
        guard state.live(now: Date().timeIntervalSince1970 * 1_000),
              UIApplication.shared.applicationState == .active, UIApplication.shared.isProtectedDataAvailable else { stop(); return }
        if IncomingCalls.shared.hasRingingPresentation { pausePlayback(); return }
        let currentWaiting = ChatSessionAudio.shared.active || IncomingCalls.shared.systemAudioOwned
        if waiting != currentWaiting { releasePlayer(); waiting = currentWaiting }
        guard player == nil else { return }
        do {
            if !waiting {
                let session = AVAudioSession.sharedInstance()
                previousCategory = (session.category, session.mode, session.categoryOptions)
                try session.setCategory(.ambient, mode: .default, options: [.mixWithOthers])
                changedCategory = true
                try session.setActive(true)
                ownsAmbientSession = true
            }
            // Call waiting uses the already active route/category and a short,
            // quiet signal. It must not reconfigure or deactivate call audio.
            let value = try AVAudioPlayer(data: Self.tone(waiting: waiting))
            value.numberOfLoops = -1
            value.volume = waiting ? 0.18 : 0.6
            guard value.prepareToPlay(), value.play() else { stop(); return }
            player = value
        } catch { stop() }
    }

    func stop() {
        state.stop()
        timer?.invalidate()
        timer = nil
        releasePlayer()
    }

    func shutdown(epoch: UInt64) { if state.admit(epoch: epoch) { stop() } }

    /// A pending system presentation may fail. Keep its lease until JS confirms
    /// takeover, so a rejected or stale push cannot silence a valid in-app alert.
    func pausePlayback() { releasePlayer() }

    private func releasePlayer() {
        player?.stop()
        player = nil
        if changedCategory {
            let session = AVAudioSession.sharedInstance()
            if !ChatSessionAudio.shared.active && !IncomingCalls.shared.systemAudioOwned && session.category == .ambient {
                if ownsAmbientSession { try? session.setActive(false, options: .notifyOthersOnDeactivation) }
                if let previousCategory {
                    try? session.setCategory(previousCategory.0, mode: previousCategory.1, options: previousCategory.2)
                }
            }
            ownsAmbientSession = false
            changedCategory = false
            previousCategory = nil
        }
    }

    private static func tone(waiting: Bool) -> Data {
        let rate = 16_000
        let count = rate * (waiting ? 8 : 3)
        var data = Data()
        func text(_ value: String) { data.append(contentsOf: value.utf8) }
        func u16(_ value: UInt16) { var bytes = value.littleEndian; withUnsafeBytes(of: &bytes) { data.append(contentsOf: $0) } }
        func u32(_ value: UInt32) { var bytes = value.littleEndian; withUnsafeBytes(of: &bytes) { data.append(contentsOf: $0) } }
        text("RIFF"); u32(UInt32(36 + count * 2)); text("WAVEfmt "); u32(16)
        u16(1); u16(1); u32(UInt32(rate)); u32(UInt32(rate * 2)); u16(2); u16(16)
        text("data"); u32(UInt32(count * 2))
        for index in 0..<count {
            let seconds = Double(index) / Double(rate)
            let first = seconds < (waiting ? 0.12 : 0.28)
            let second = seconds >= (waiting ? 0.22 : 0.42) && seconds < (waiting ? 0.34 : 0.7)
            let start = first ? 0.0 : (waiting ? 0.22 : 0.42)
            let end = first ? (waiting ? 0.12 : 0.28) : (waiting ? 0.34 : 0.7)
            let envelope = (first || second) ? max(0, min(1, min((seconds - start) / 0.015, (end - seconds) / 0.015))) : 0
            let frequency = waiting ? 660.0 : (first ? 523.25 : 659.25)
            let sample = Int16((sin(2 * .pi * frequency * seconds) * envelope * 12_000).rounded())
            u16(UInt16(bitPattern: sample))
        }
        return data
    }
}
