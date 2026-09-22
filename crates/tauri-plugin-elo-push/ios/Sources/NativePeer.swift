import Foundation
import AVFoundation
import WebRTC

/// Native media has no profile keys. SDP/ICE is supplied only after elo's signed
/// admission and recipient-encrypted signaling have been verified by the client.
@MainActor final class NativePeer: NSObject, RTCPeerConnectionDelegate {
    static let factory: RTCPeerConnectionFactory = {
        RTCInitializeSSL()
        return RTCPeerConnectionFactory(encoderFactory: RTCDefaultVideoEncoderFactory(), decoderFactory: RTCDefaultVideoDecoderFactory())
    }()
    let id: String
    private(set) var pc: RTCPeerConnection!
    private var audio: RTCAudioTrack?
    private var camera: RTCVideoTrack?
    private var capturer: RTCCameraVideoCapturer?
    private var channels: [RTCRtpTransceiver] = []
    private var candidates: [RTCIceCandidate] = []
    private var signals: [[String: Any]] = []
    private var acceptedOffer: String?
    private var acceptedAnswer: String?
    private var stopped = false
    private var connection = "new"
    private var revision = 0
    private var speakerMuted = false
    private var state: [String: Bool] = [:]

    init(id: String, servers: [[String: Any]]) throws {
        self.id = id
        super.init()
        let config = RTCConfiguration()
        config.sdpSemantics = .unifiedPlan
        config.bundlePolicy = .maxBundle
        config.continualGatheringPolicy = .gatherContinually
        config.iceServers = try servers.map { value in
            let urls = (value["urls"] as? [String]) ?? (value["urls"] as? String).map { [$0] } ?? []
            guard !urls.isEmpty, urls.count <= 8,
                urls.allSatisfy({ $0.count <= 2048 && ["stun:", "stuns:", "turn:", "turns:"].contains(where: $0.hasPrefix) }) else { throw MediaError.invalid }
            return RTCIceServer(urlStrings: urls, username: value["username"] as? String, credential: value["credential"] as? String)
        }
        guard let peer = Self.factory.peerConnection(with: config, constraints: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil), delegate: self) else { throw MediaError.unavailable }
        pc = peer
        let session = RTCAudioSession.sharedInstance()
        session.useManualAudio = IncomingCalls.shared.ownsAudio
        session.isAudioEnabled = !IncomingCalls.shared.ownsAudio || IncomingCalls.shared.audioActive
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        do {
            try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth, .defaultToSpeaker])
        } catch { peer.close(); throw MediaError.unavailable }
        audio = Self.factory.audioTrack(with: Self.factory.audioSource(with: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)), trackId: "microphone")
        audio?.isEnabled = false
    }
    enum MediaError: Error { case invalid, unavailable, ended, permission }
    static func permission(video: Bool) async throws {
        guard await AVCaptureDevice.requestAccess(for: .audio) else { throw MediaError.permission }
        if video {
            guard await AVCaptureDevice.requestAccess(for: .video) else { throw MediaError.permission }
        }
    }
    private func live() throws { if stopped { throw MediaError.ended } }
    private func emit(_ signal: [String: Any]) {
        guard !stopped else { return }
        guard signals.count < 256 else { stop(); connection = "failed"; return }
        signals.append(signal)
    }
    func update(_ next: [String: Bool], speakerMuted: Bool) async throws {
        try live()
        guard next["screen_published"] != true else { throw MediaError.invalid }
        let video = next["video_published"] == true
        if video && camera == nil {
            try await Self.permission(video: true)
            try live()
            guard let device = RTCCameraVideoCapturer.captureDevices().first(where: { $0.position == .front }) ?? RTCCameraVideoCapturer.captureDevices().first else { throw MediaError.unavailable }
            let formats = RTCCameraVideoCapturer.supportedFormats(for: device)
            guard let format = formats.filter({ CMVideoFormatDescriptionGetDimensions($0.formatDescription).width <= 1280 }).max(by: {
                CMVideoFormatDescriptionGetDimensions($0.formatDescription).width < CMVideoFormatDescriptionGetDimensions($1.formatDescription).width
            }) ?? formats.first else { throw MediaError.unavailable }
            let source = Self.factory.videoSource()
            let capture = RTCCameraVideoCapturer(delegate: source)
            let track = Self.factory.videoTrack(with: source, trackId: "camera")
            let fps = Int(min(30, format.videoSupportedFrameRateRanges.map { $0.maxFrameRate }.max() ?? 30))
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                capture.startCapture(with: device, format: format, fps: fps) { error in
                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                }
            }
            if stopped { await capture.stopCapture(); throw MediaError.ended }
            capturer = capture; camera = track; revision += 1
        }
        if !video, let capture = capturer {
            capturer = nil; camera = nil; revision += 1
            await capture.stopCapture()
            try live()
        }
        state = next
        audio?.isEnabled = next["audio_muted"] != true
        self.speakerMuted = speakerMuted
        try applyTracks()
    }
    func muteMicrophone(_ muted: Bool) {
        state["audio_muted"] = muted
        audio?.isEnabled = !muted
    }
    func muteSpeaker(_ muted: Bool) {
        speakerMuted = muted
        channels.first?.receiver.track?.isEnabled = !muted
    }
    private func applyTracks() throws {
        try live()
        guard channels.count == 3 else { return }
        channels[0].sender.track = audio
        channels[1].sender.track = camera
        channels[2].sender.track = nil
        channels[0].receiver.track?.isEnabled = !speakerMuted
    }
    func offer(restart: Bool) async throws {
        try live()
        if channels.isEmpty {
            let settings = RTCRtpTransceiverInit(); settings.direction = .sendRecv
            channels = [RTCRtpMediaType.audio, .video, .video].compactMap { pc.addTransceiver(of: $0, init: settings) }
            guard channels.count == 3 else { throw MediaError.invalid }
            try applyTracks()
        }
        if pc.signalingState == .stable {
            let constraints = RTCMediaConstraints(mandatoryConstraints: restart ? ["IceRestart": "true"] : nil, optionalConstraints: nil)
            let offer: RTCSessionDescription = try await withCheckedThrowingContinuation { continuation in
                pc.offer(for: constraints) { sdp, error in
                    if let sdp = sdp { continuation.resume(returning: sdp) } else { continuation.resume(throwing: error ?? MediaError.unavailable) }
                }
            }
            try live(); try await local(offer)
        }
        if pc.signalingState == .haveLocalOffer, let sdp = pc.localDescription {
            emit(["type": "offer", "sdp": sdp.sdp])
        }
    }
    private func local(_ sdp: RTCSessionDescription) async throws {
        try live()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pc.setLocalDescription(sdp) { error in
                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
        try live()
    }
    private func add(_ candidate: RTCIceCandidate) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pc.add(candidate) { error in
                if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
        try live()
    }
    func signal(_ value: [String: Any]) async throws {
        try live()
        switch value["type"] as? String {
        case "request_offer": try await offer(restart: true)
        case "ice":
            guard let raw = value["candidate"] as? String, raw.count <= 8192,
                let line = value["sdp_mline_index"] as? Int, (0...2).contains(line) else { throw MediaError.invalid }
            let candidate = RTCIceCandidate(sdp: raw, sdpMLineIndex: Int32(line), sdpMid: value["sdp_mid"] as? String)
            if pc.remoteDescription != nil { try await add(candidate) }
            else { guard candidates.count < 128 else { throw MediaError.invalid }; candidates.append(candidate) }
        case "offer", "answer":
            let answering = value["type"] as? String == "answer"
            guard let raw = value["sdp"] as? String, raw.utf8.count <= 131072 else { throw MediaError.invalid }
            if answering && pc.signalingState == .stable { return }
            if raw == (answering ? acceptedAnswer : acceptedOffer) {
                if answering { return }
                if pc.signalingState == .stable, let sdp = pc.localDescription, sdp.type == .answer {
                    emit(["type": "answer", "sdp": sdp.sdp]); return
                }
            }
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                pc.setRemoteDescription(RTCSessionDescription(type: answering ? .answer : .offer, sdp: raw)) { error in
                    if let error = error { continuation.resume(throwing: error) } else { continuation.resume() }
                }
            }
            try live()
            if answering { acceptedAnswer = raw } else { acceptedOffer = raw }
            let pending = candidates; candidates.removeAll()
            for candidate in pending { try await add(candidate) }
            if !answering {
                if channels.isEmpty {
                    channels = pc.transceivers.filter { $0.mid != nil }
                    guard channels.count == 3, channels.map({ $0.mediaType }) == [.audio, .video, .video] else { throw MediaError.invalid }
                    for channel in channels {
                        var error: NSError?
                        channel.setDirection(.sendRecv, error: &error)
                        if let error = error { throw error }
                    }
                }
                try applyTracks()
                let answer: RTCSessionDescription = try await withCheckedThrowingContinuation { continuation in
                    pc.answer(for: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)) { sdp, error in
                        if let sdp = sdp { continuation.resume(returning: sdp) } else { continuation.resume(throwing: error ?? MediaError.unavailable) }
                    }
                }
                try live(); try await local(answer)
                if let sdp = pc.localDescription { emit(["type": "answer", "sdp": sdp.sdp]) }
            }
            revision += 1
        default: throw MediaError.invalid
        }
    }
    func videoTrack(_ id: String) -> RTCVideoTrack? {
        if id == "local-camera" { return camera }
        if id == "remote-camera", channels.count == 3 { return channels[1].receiver.track as? RTCVideoTrack }
        if id == "remote-screen", channels.count == 3 { return channels[2].receiver.track as? RTCVideoTrack }
        return nil
    }
    func poll() -> [String: Any] {
        let pending = signals; signals.removeAll()
        var tracks: [[String: Any]] = []
        if camera != nil { tracks.append(["id": "local-camera", "source": "camera", "local": true]) }
        for (id, source) in [("remote-camera", "camera"), ("remote-screen", "screen")] {
            if videoTrack(id) != nil { tracks.append(["id": id, "source": source, "local": false]) }
        }
        return ["connection": connection, "revision": revision, "signals": pending, "tracks": tracks]
    }
    func stop() {
        guard !stopped else { return }
        stopped = true
        audio?.isEnabled = false
        capturer?.stopCapture(); capturer = nil; camera = nil; audio = nil
        pc?.close()
        channels.removeAll(); candidates.removeAll(); signals.removeAll()
        connection = "closed"; revision += 1
    }
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didChange stateChanged: RTCSignalingState) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didAdd stream: RTCMediaStream) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didRemove stream: RTCMediaStream) {}
    nonisolated func peerConnectionShouldNegotiate(_ peerConnection: RTCPeerConnection) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceGatheringState) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didRemove candidates: [RTCIceCandidate]) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didOpen dataChannel: RTCDataChannel) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceConnectionState) {}
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCPeerConnectionState) {
        Task { @MainActor [weak self] in
            guard let self = self, !self.stopped else { return }
            self.connection = [.new: "new", .connecting: "connecting", .connected: "connected", .disconnected: "disconnected", .failed: "failed", .closed: "closed"][newState] ?? "failed"
        }
    }
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didGenerate candidate: RTCIceCandidate) {
        Task { @MainActor [weak self] in
            self?.emit(["type": "ice", "candidate": candidate.sdp, "sdp_mid": candidate.sdpMid as Any? ?? NSNull(), "sdp_mline_index": Int(candidate.sdpMLineIndex)])
        }
    }
    nonisolated func peerConnection(_ peerConnection: RTCPeerConnection, didStartReceivingOn transceiver: RTCRtpTransceiver) {
        Task { @MainActor [weak self] in self?.revision += 1 }
    }
}
