import Foundation
import UIKit
import WebKit
import WebRTC

@MainActor final class NativeMedia {
    static let shared = NativeMedia()
    weak var webView: WKWebView?
    private(set) var peer: NativePeer?
    private var host: UIView?
    private var renderers: [String: (RTCVideoTrack, RTCMTLVideoView)] = [:]
    private var originalOpaque = true
    private var originalBackground: UIColor?
    private var originalScrollBackground: UIColor?

    func stopAll() {
        peer?.stop(); peer = nil
        clearRenderers()
    }
    private func clearRenderers() {
        guard host != nil else { return }
        for (_, (track, view)) in renderers { track.remove(view); view.removeFromSuperview() }
        renderers.removeAll()
        host?.removeFromSuperview(); host = nil
        if let web = webView {
            web.isOpaque = originalOpaque
            web.backgroundColor = originalBackground
            web.scrollView.backgroundColor = originalScrollBackground
        }
    }
    private func render(_ frames: [[String: Any]], peer: NativePeer) throws {
        guard frames.count <= 4 else { throw NativePeer.MediaError.invalid }
        if frames.isEmpty { clearRenderers(); return }
        guard let web = webView, let parent = web.superview else { throw NativePeer.MediaError.unavailable }
        if host == nil {
            originalOpaque = web.isOpaque
            originalBackground = web.backgroundColor
            originalScrollBackground = web.scrollView.backgroundColor
            let view = UIView(frame: web.frame)
            view.isUserInteractionEnabled = false
            view.backgroundColor = UIColor(red: 16/255, green: 20/255, blue: 18/255, alpha: 1)
            view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            parent.insertSubview(view, belowSubview: web)
            host = view
            web.isOpaque = false; web.backgroundColor = .clear; web.scrollView.backgroundColor = .clear
        }
        host?.frame = web.frame
        var live = Set<String>()
        for frame in frames {
            guard let id = frame["track"] as? String, let track = peer.videoTrack(id),
                let x = frame["x"] as? Double, let y = frame["y"] as? Double,
                let width = frame["width"] as? Double, let height = frame["height"] as? Double,
                let viewport = frame["viewport_width"] as? Double,
                [x,y,width,height,viewport].allSatisfy({ $0.isFinite }),
                viewport > 0, width >= 0, height >= 0, width <= 4096, height <= 4096,
                abs(x) <= 4096, abs(y) <= 4096 else { throw NativePeer.MediaError.invalid }
            live.insert(id)
            let view: RTCMTLVideoView
            if let (oldTrack, existing) = renderers[id], oldTrack === track { view = existing }
            else {
                if let (oldTrack, existing) = renderers[id] { oldTrack.remove(existing); existing.removeFromSuperview() }
                view = RTCMTLVideoView(frame: .zero)
                view.isUserInteractionEnabled = false
                view.clipsToBounds = true
                view.layer.cornerRadius = 12
                track.add(view)
                renderers[id] = (track, view)
                host?.addSubview(view)
            }
            let scale = web.bounds.width / viewport
            view.transform = .identity
            view.frame = CGRect(x: x * scale, y: y * scale, width: width * scale, height: height * scale)
            view.videoContentMode = frame["fit"] as? Bool == true ? .scaleAspectFit : .scaleAspectFill
            if frame["mirror"] as? Bool == true { view.transform = CGAffineTransform(scaleX: -1, y: 1) }
            host?.bringSubviewToFront(view)
        }
        for id in Array(renderers.keys) where !live.contains(id) {
            if let (track, view) = renderers.removeValue(forKey: id) { track.remove(view); view.removeFromSuperview() }
        }
    }
    func command(_ request: [String: Any]) async throws -> [String: Any] {
        let op = request["op"] as? String ?? ""
        if op == "shutdown" { stopAll(); return [:] }
        if op == "permissions" {
            try await NativePeer.permission(video: request["video"] as? Bool == true)
            return [:]
        }
        guard let id = request["id"] as? String, UUID(uuidString: id) != nil else { throw NativePeer.MediaError.invalid }
        if op == "health" { return ["live": peer?.id == id] }
        if op == "end_call" {
            if peer?.id == id {
                stopAll()
            }
            if let callId = request["call_id"] as? String { IncomingCalls.shared.end(callId) }
            return [:]
        }
        if op == "stop" {
            if peer?.id == id { stopAll() }
            return [:]
        }
        if op == "start" {
            guard peer == nil, let servers = request["ice_servers"] as? [[String: Any]], servers.count <= 16 else { throw NativePeer.MediaError.invalid }
            peer = try NativePeer(id: id, servers: servers)
            return [:]
        }
        guard let peer = peer, peer.id == id else { throw NativePeer.MediaError.ended }
        switch op {
        case "poll": return peer.poll()
        case "offer": try await peer.offer(restart: request["restart"] as? Bool == true)
        case "signal":
            guard let signal = request["signal"] as? [String: Any] else { throw NativePeer.MediaError.invalid }
            try await peer.signal(signal)
        case "update":
            guard let state = request["state"] as? [String: Bool] else { throw NativePeer.MediaError.invalid }
            try await peer.update(state, speakerMuted: request["speaker_muted"] as? Bool == true)
        case "speaker": peer.muteSpeaker(request["muted"] as? Bool == true)
        case "render":
            guard let frames = request["frames"] as? [[String: Any]] else { throw NativePeer.MediaError.invalid }
            try render(frames, peer: peer)
        default: throw NativePeer.MediaError.invalid
        }
        return [:]
    }
}
