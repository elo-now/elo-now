import Foundation
import UIKit
import WebKit
import WebRTC
import LiveKit

@MainActor final class NativeMedia {
    static let shared = NativeMedia()
    weak var webView: WKWebView?
    private(set) var peer: NativePeer?
    private var group: NativeGroup?
    private var groupStopping: Task<Void, Never>?
    private var systemMutes: [String: SystemMutePolicy] = [:]
    private var groupPolicy: (id: String, value: NativeGroupPolicy)?
    private var groupRenderers: [String: LiveKit.VideoView] = [:]
    private var host: UIView?
    private var renderers: [String: (RTCVideoTrack, RTCMTLVideoView)] = [:]
    private var originalOpaque = true
    private var originalBackground: UIColor?
    private var originalScrollBackground: UIColor?

    func stopAll(preserveGroupPolicy: Bool = false) {
        if !preserveGroupPolicy { groupPolicy = nil; systemMutes.removeAll() }
        peer?.stop(); peer = nil
        if let group = group { groupStopping = group.stop(); self.group = nil }
        clearRenderers()
    }
    func stop(id: String, preserveGroupPolicy: Bool = false) {
        if peer?.id == id || group?.id == id { stopAll(preserveGroupPolicy: preserveGroupPolicy) }
        if !preserveGroupPolicy, groupPolicy?.id == id { groupPolicy = nil }
        if !preserveGroupPolicy { systemMutes.removeValue(forKey: id) }
    }
    func beginSystemMute(id: String) -> UInt64 {
        var policy = systemMutes[id] ?? SystemMutePolicy()
        let revision = policy.begin()
        systemMutes[id] = policy
        // Both mute and unmute intents close capture until a matching signed
        // Media grant comes back. A media reset for this ID keeps the fence.
        setSystemMute(id: id, muted: true)
        return revision
    }
    func systemMuted(id: String, requested: Bool, revision: UInt64?) -> Bool {
        systemMutes[id]?.muted(requested: requested, revision: revision) ?? requested
    }
    func systemMuteRevision(id: String) -> UInt64? { systemMutes[id]?.revision }
    private func reconcileSystemMute(id: String, state: [String: Bool], revision: UInt64?) {
        guard systemMutes[id] == nil || systemMutes[id]?.revision == revision else { return }
        IncomingCalls.shared.reconcileMute(capture: id, muted: state["audio_muted"] == true)
    }
    func systemAudioActivated() { group?.systemAudio(active: true) }
    func systemAudioDeactivated() { group?.systemAudio(active: false) }
    func setSystemMute(id: String, muted: Bool) {
        if peer?.id == id { peer?.muteMicrophone(muted) }
        if group?.id == id { group?.muteMicrophone(muted) }
    }
    private func clearRenderers() {
        guard host != nil else { return }
        for (_, (track, view)) in renderers { track.remove(view); view.removeFromSuperview() }
        renderers.removeAll()
        for view in groupRenderers.values { view.track = nil; view.removeFromSuperview() }
        groupRenderers.removeAll()
        host?.removeFromSuperview(); host = nil
        if let web = webView {
            web.isOpaque = originalOpaque
            web.backgroundColor = originalBackground
            web.scrollView.backgroundColor = originalScrollBackground
        }
    }
    private func ensureHost() throws -> WKWebView {
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
        return web
    }
    private func renderGroup(_ frames: [[String: Any]], group: NativeGroup) throws {
        guard frames.count <= 128 else { throw NativePeer.MediaError.invalid }
        if frames.isEmpty { clearRenderers(); return }
        let web = try ensureHost()
        var live = Set<String>()
        for frame in frames {
            guard let id = frame["track"] as? String, let track = group.videoTrack(id),
                let x = frame["x"] as? Double, let y = frame["y"] as? Double,
                let width = frame["width"] as? Double, let height = frame["height"] as? Double,
                let viewport = frame["viewport_width"] as? Double,
                [x,y,width,height,viewport].allSatisfy({ $0.isFinite }),
                viewport > 0, width >= 0, height >= 0, width <= 4096, height <= 4096,
                abs(x) <= 4096, abs(y) <= 4096 else { throw NativePeer.MediaError.invalid }
            live.insert(id)
            let view = groupRenderers[id] ?? LiveKit.VideoView(frame: .zero)
            view.track = track
            view.isUserInteractionEnabled = false
            view.clipsToBounds = true
            view.layer.cornerRadius = 12
            view.layoutMode = frame["fit"] as? Bool == true ? .fit : .fill
            view.mirrorMode = frame["mirror"] as? Bool == true ? .mirror : .off
            let scale = web.bounds.width / viewport
            view.frame = CGRect(x:x * scale,y:y * scale,width:width * scale,height:height * scale)
            if groupRenderers[id] == nil { groupRenderers[id] = view; host?.addSubview(view) }
        }
        for id in Array(groupRenderers.keys) where !live.contains(id) {
            let view = groupRenderers.removeValue(forKey:id); view?.track = nil; view?.removeFromSuperview()
        }
    }
    private func render(_ frames: [[String: Any]], peer: NativePeer) throws {
        guard frames.count <= 4 else { throw NativePeer.MediaError.invalid }
        if frames.isEmpty { clearRenderers(); return }
        let web = try ensureHost()
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
        if op == "shutdown" { stopAll(); await groupStopping?.value; return [:] }
        if op == "permissions" {
            try await NativePeer.permission(video: request["video"] as? Bool == true)
            return [:]
        }
        guard let id = request["id"] as? String, UUID(uuidString: id) != nil else { throw NativePeer.MediaError.invalid }
        if op == "system_call_start" { try await IncomingCalls.shared.startOutgoing(request); return [:] }
        if op == "system_call_connected" { try IncomingCalls.shared.outgoingConnected(UUID(uuidString: id)!); return [:] }
        if op == "system_call_end" { IncomingCalls.shared.outgoingEnded(UUID(uuidString: id)!); return [:] }
        if op == "health" { return ["live": peer?.id == id || group?.id == id] }
        if op == "end_call" || op == "stop" {
            stop(id: id)
            await groupStopping?.value
            return [:]
        }
        if op == "group_reset", request["key"] == nil {
            guard peer == nil, group == nil || group?.id == id else { throw NativePeer.MediaError.ended }
            stop(id: id, preserveGroupPolicy: true)
            await groupStopping?.value
            return [:]
        }
        if op == "group_start" || op == "group_reset" {
            guard let key = request["key"] as? String, let epoch = request["epoch"] as? UInt64,
                let participants = request["participants"] as? [String], let url = request["url"] as? String,
                let credential = request["credential"] as? String,
                let token = request["token"] as? String else { throw NativePeer.MediaError.invalid }
            if let current = group {
                guard current.id == id, epoch >= current.epoch else { throw NativePeer.MediaError.ended }
                if current.epoch == epoch {
                    guard current.matches(key:key,epoch:epoch,participants:participants,credential:credential) else {
                        throw NativePeer.MediaError.invalid
                    }
                    return [:]
                }
                guard op == "group_reset" else { throw NativePeer.MediaError.invalid }
                stop(id:id, preserveGroupPolicy: true)
            }
            await groupStopping?.value
            guard peer == nil, group == nil else { throw NativePeer.MediaError.invalid }
            var policy = groupPolicy?.id == id ? groupPolicy!.value : NativeGroupPolicy()
            try policy.accept(epoch:epoch,key:key,participants:participants,credential:credential)
            let active = try NativeGroup(id:id,key:key,epoch:epoch,participants:participants,credential:credential)
            groupPolicy = (id,policy)
            group = active
            do {
                try await active.connect(url:url,token:token)
                guard group === active else { throw NativePeer.MediaError.ended }
                if let state = request["state"] as? [String:Bool] { try await active.update(state,speakerMuted:false,systemMuteRevision:request["system_mute_revision"] as? UInt64) }
                return [:]
            } catch {
                if group === active { stop(id:id, preserveGroupPolicy:true) }
                await active.stop().value
                throw error
            }
        }
        if let group = group, group.id == id {
            switch op {
            case "poll", "snapshot": return group.poll()
            case "update":
                guard let state = request["state"] as? [String:Bool] else { throw NativePeer.MediaError.invalid }
                try await group.update(state,speakerMuted:request["speaker_muted"] as? Bool == true,systemMuteRevision:request["system_mute_revision"] as? UInt64)
                if self.group === group { reconcileSystemMute(id: id, state: state, revision: request["system_mute_revision"] as? UInt64) }
            case "speaker":
                if let credential = request["credential"] as? String { try group.muteParticipant(credential, muted:request["muted"] as? Bool == true) }
                else { group.muteSpeaker(request["muted"] as? Bool == true) }
            case "render":
                guard let frames = request["frames"] as? [[String:Any]] else { throw NativePeer.MediaError.invalid }
                try renderGroup(frames,group:group)
            default: throw NativePeer.MediaError.invalid
            }
            return [:]
        }
        if op == "start" {
            await groupStopping?.value
            guard peer == nil, group == nil, let servers = request["ice_servers"] as? [[String: Any]], servers.count <= 16 else { throw NativePeer.MediaError.invalid }
            peer = try NativePeer(id: id, servers: servers)
            return [:]
        }
        guard let peer = peer, peer.id == id else { throw NativePeer.MediaError.ended }
        switch op {
        case "reset":
            guard let servers = request["ice_servers"] as? [[String: Any]] else { throw NativePeer.MediaError.invalid }
            clearRenderers()
            try peer.reset(servers: servers)
        case "poll": return peer.poll()
        case "snapshot": return peer.poll(drain: false)
        case "offer": try await peer.offer(restart: request["restart"] as? Bool == true)
        case "signal":
            guard let signal = request["signal"] as? [String: Any] else { throw NativePeer.MediaError.invalid }
            try await peer.signal(signal)
        case "update":
            guard let state = request["state"] as? [String: Bool] else { throw NativePeer.MediaError.invalid }
            try await peer.update(state, speakerMuted: request["speaker_muted"] as? Bool == true, systemMuteRevision: request["system_mute_revision"] as? UInt64)
            if self.peer === peer { reconcileSystemMute(id: id, state: state, revision: request["system_mute_revision"] as? UInt64) }
        case "speaker": peer.muteSpeaker(request["muted"] as? Bool == true)
        case "render":
            guard let frames = request["frames"] as? [[String: Any]] else { throw NativePeer.MediaError.invalid }
            try render(frames, peer: peer)
        default: throw NativePeer.MediaError.invalid
        }
        return [:]
    }
}
