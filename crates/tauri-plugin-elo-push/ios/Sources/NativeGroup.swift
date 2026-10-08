import EloDiagnostics
import Foundation
import AVFoundation
import CryptoKit
import LiveKit

/// One admitted group epoch. Rust owns membership, provider access and key
/// exchange; the SDK receives only a short-lived media token and raw media key.
@MainActor final class NativeGroup: NSObject, RoomDelegate {
    let id: String
    let epoch: UInt64
    private let credential: String
    private let keyDigest: SHA256.Digest
    private let permitted: Set<String>
    private let room: Room
    private let keys: BaseKeyProvider
    private var stopped = false
    private var failed = false
    private var stopping: Task<Void, Never>?
    private var speakerMuted = false
    private var mutedParticipants = Set<String>()
    private var state: [String: Bool] = ["audio_muted": true, "video_published": false, "screen_published": false]
    private var revision = 0
    private var signature = ""
    private var subscribing = Set<String>()

    init(id: String, key: String, epoch: UInt64, participants: [String], credential: String) throws {
        guard UUID(uuidString: id) != nil, epoch > 0, key.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
            (1...128).contains(participants.count), Set(participants).count == participants.count, participants.contains(credential),
            participants.allSatisfy({ $0.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil }) else {
            throw NativePeer.MediaError.invalid
        }
        self.id = id; self.epoch = epoch; self.permitted = Set(participants); self.credential = credential
        self.keyDigest = SHA256.hash(data: Data(key.utf8))
        keys = BaseKeyProvider(options: KeyProviderOptions(sharedKey: true,
            discardFrameWhenCryptorNotReady: true, keyDerivationAlgorithm: .hkdf))
        var bytes = Data(stride(from: 0, to: 64, by: 2).map { offset in
            let start = key.index(key.startIndex, offsetBy: offset)
            return UInt8(key[start..<key.index(start, offsetBy: 2)], radix: 16)!
        })
        // ArrayBuffer keys in JS use HKDF, not the SDK's default passphrase KDF.
        keys.setKey(keyData: bytes, index: 0)
        bytes.resetBytes(in: 0..<bytes.count)
        room = Room(roomOptions: RoomOptions(adaptiveStream: true, dynacast: true,
            encryptionOptions: EncryptionOptions(keyProvider: keys)))
        super.init()
        // CallKit / ChatSessionAudio exclusively own category and activation.
        AudioManager.shared.audioSession.isAutomaticConfigurationEnabled = false
        AudioManager.shared.audioSession.isAutomaticDeactivationEnabled = false
        try AudioManager.shared.setEngineAvailability(IncomingCalls.shared.systemAudioOwned && !IncomingCalls.shared.audioActivated ? .none : .default)
        AudioManager.shared.isMicrophoneMuted = true
        room.add(delegate: self)
    }

    func matches(key: String, epoch: UInt64, participants: [String], credential: String) -> Bool {
        !stopped && self.epoch == epoch && self.credential == credential && self.permitted == Set(participants)
            && self.keyDigest == SHA256.hash(data: Data(key.utf8))
    }

    func connect(url: String, token: String) async throws {
        guard !stopped, url.count <= 2048, token.count <= 16384, !token.isEmpty,
            let address = URLComponents(string: url), address.scheme == "wss", address.host != nil,
            address.user == nil, address.password == nil, address.fragment == nil else { throw NativePeer.MediaError.invalid }
        do {
            try await room.connect(url: url, token: token, connectOptions: ConnectOptions(autoSubscribe: false,
                reconnectAttempts: 3, socketConnectTimeoutInterval: 10, primaryTransportConnectTimeout: 10,
                publisherTransportConnectTimeout: 10))
            guard !stopped, let identity = room.localParticipant.identity?.stringValue, identity == credential else {
                throw NativePeer.MediaError.ended
            }
            subscribeAdmitted()
        } catch {
            EloDiagnostics.mediaFailure(error, stage: "group_connect_failed")
            await stop().value
            throw error
        }
    }

    private func subscribeAdmitted() {
        guard !stopped else { return }
        for participant in room.remoteParticipants.values {
            guard let credential = participant.identity?.stringValue, permitted.contains(credential) else { continue }
            for publication in participant.trackPublications.values {
                guard let publication = publication as? RemoteTrackPublication,
                    publication.encryptionType == .gcm, publication.track == nil,
                    subscribing.insert(publication.sid.stringValue).inserted else { continue }
                let sid = publication.sid.stringValue
                Task { @MainActor [weak self] in
                    guard let self = self, !self.stopped else { return }
                    defer { self.subscribing.remove(sid) }
                    do { try await publication.set(subscribed: true) }
                    catch { if !self.stopped { self.failed = true } }
                }
            }
        }
    }

    func update(_ next: [String: Bool], speakerMuted: Bool, systemMuteRevision: UInt64? = nil) async throws {
        guard !stopped else { throw NativePeer.MediaError.ended }
        // iOS's existing screen-share control remains unavailable; receiving
        // someone else's screen remains supported through native VideoView.
        guard next["screen_published"] != true else { throw NativePeer.MediaError.invalid }
        if next["audio_muted"] != true || next["video_published"] == true {
            try await NativePeer.permission(video: next["video_published"] == true)
        }
        guard !stopped else { throw NativePeer.MediaError.ended }
        try await room.localParticipant.setMicrophone(enabled: !NativeMedia.shared.systemMuted(id: id, requested: next["audio_muted"] == true, revision: systemMuteRevision))
        guard !stopped else { throw NativePeer.MediaError.ended }
        try await room.localParticipant.setCamera(enabled: next["video_published"] == true)
        guard !stopped else { throw NativePeer.MediaError.ended }
        state = next
        state["audio_muted"] = NativeMedia.shared.systemMuted(id: id, requested: next["audio_muted"] == true, revision: systemMuteRevision)
        AudioManager.shared.isMicrophoneMuted = state["audio_muted"] == true
        muteSpeaker(speakerMuted)
    }

    func systemAudio(active: Bool) {
        guard !stopped else { return }
        do { try AudioManager.shared.setEngineAvailability(active ? .default : .none) }
        catch { failed = true; stop() }
    }

    func muteMicrophone(_ muted: Bool) {
        guard !stopped else { return }
        state["audio_muted"] = muted
        AudioManager.shared.isMicrophoneMuted = muted
        Task { @MainActor [weak self] in
            guard let self = self, !self.stopped else { return }
            do { try await self.room.localParticipant.setMicrophone(enabled: !muted) }
            catch { if !self.stopped { self.failed = true } }
            AudioManager.shared.isMicrophoneMuted = self.stopped || self.state["audio_muted"] == true
        }
    }

    func muteSpeaker(_ muted: Bool) {
        speakerMuted = muted
        for participant in room.remoteParticipants.values {
            for publication in participant.trackPublications.values {
                (publication.track as? RemoteAudioTrack)?.volume = muted || mutedParticipants.contains(participant.identity?.stringValue ?? "") ? 0 : 1
            }
        }
    }

    func muteParticipant(_ credential: String, muted: Bool) throws {
        guard !stopped, permitted.contains(credential) else { throw NativePeer.MediaError.ended }
        if muted { mutedParticipants.insert(credential) } else { mutedParticipants.remove(credential) }
        muteSpeaker(speakerMuted)
    }

    private func tracks() -> [(TrackPublication, Participant, Bool)] {
        var result: [(TrackPublication, Participant, Bool)] = []
        for participant in [room.localParticipant as Participant] + Array(room.remoteParticipants.values) {
            guard let credential = participant.identity?.stringValue, permitted.contains(credential) else { continue }
            for publication in participant.trackPublications.values where publication.encryptionType == .gcm && !publication.isMuted {
                if publication.track != nil { result.append((publication, participant, participant === room.localParticipant)) }
            }
        }
        return result.sorted { $0.0.sid.stringValue < $1.0.sid.stringValue }
    }

    func videoTrack(_ id: String) -> VideoTrack? {
        tracks().first(where: { $0.0.sid.stringValue == id })?.0.track as? VideoTrack
    }

    func poll() -> [String: Any] {
        let entries = tracks().map { publication, participant, local -> [String: Any] in
            ["id": publication.sid.stringValue, "credential": participant.identity!.stringValue,
             "source": publication.source == .screenShareVideo ? "screen" : publication.source == .camera ? "camera" : "audio",
             "local": local, "speaking": participant.isSpeaking]
        }
        let next = entries.map { "\($0["id"]!)|\($0["speaking"]!)" }.joined(separator: ":")
        if next != signature { signature = next; revision += 1 }
        let connection: String
        if stopped { connection = "closed" }
        else if failed { connection = "failed" }
        else {
            switch room.connectionState {
            case .connected: connection = "connected"
            case .connecting: connection = "connecting"
            case .reconnecting: connection = "disconnected"
            default: connection = "failed"
            }
        }
        return ["connection": connection, "revision": revision, "signals": [], "tracks": entries, "media": state]
    }

    @discardableResult func stop() -> Task<Void, Never> {
        if let stopping = stopping { return stopping }
        stopped = true
        AudioManager.shared.isMicrophoneMuted = true
        try? AudioManager.shared.setEngineAvailability(.none)
        room.remove(delegate: self)
        let task = Task { @MainActor [room, keys] in
            await room.disconnect()
            // Discard this epoch after capture/publications have stopped.
            keys.setKey(keyData: Data(repeating: 0, count: 32), index: 0)
        }
        stopping = task
        return task
    }

    nonisolated func room(_ room: Room, participant: RemoteParticipant, didPublishTrack publication: RemoteTrackPublication) {
        Task { @MainActor [weak self] in self?.subscribeAdmitted() }
    }
    nonisolated func room(_ room: Room, participantDidConnect participant: RemoteParticipant) {
        Task { @MainActor [weak self] in self?.subscribeAdmitted() }
    }
    nonisolated func room(_ room: Room, participant: RemoteParticipant, didSubscribeTrack publication: RemoteTrackPublication) {
        Task { @MainActor [weak self] in guard let self = self, !self.stopped else { return }; self.muteSpeaker(self.speakerMuted) }
    }
    nonisolated func room(_ room: Room, trackPublication: TrackPublication, didUpdateE2EEState state: E2EEState) {
        guard ![.new, .ok, .key_ratcheted].contains(state) else { return }
        Task { @MainActor [weak self] in guard let self = self, !self.stopped else { return }; self.failed = true; self.stop() }
    }
}
