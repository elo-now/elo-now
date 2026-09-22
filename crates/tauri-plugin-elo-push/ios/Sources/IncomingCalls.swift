import Foundation
import UIKit
import PushKit
import CallKit
import AVFAudio
import WebRTC

/// No profile key or message plaintext is accessible from this native ring path.
final class IncomingCalls: NSObject, PKPushRegistryDelegate, CXProviderDelegate, URLSessionTaskDelegate {
    static let shared = IncomingCalls()
    private let prefs = UserDefaults.standard
    private var registry: PKPushRegistry?
    private var provider: CXProvider!
    private var timer: Timer?
    private var answer: CXAnswerCallAction?
    private var checking = false
    private(set) var audioActive = false
    var ownsAudio: Bool { pending != nil }
    func provider(_ provider: CXProvider, didActivate audioSession: AVAudioSession) {
        audioActive = true
        RTCAudioSession.sharedInstance().audioSessionDidActivate(audioSession)
        RTCAudioSession.sharedInstance().isAudioEnabled = true
    }
    func provider(_ provider: CXProvider, didDeactivate audioSession: AVAudioSession) {
        audioActive = false
        RTCAudioSession.sharedInstance().isAudioEnabled = false
        RTCAudioSession.sharedInstance().audioSessionDidDeactivate(audioSession)
    }
    private lazy var session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    private func event(_ call:[String:Any], action:String, muted:Bool? = nil) {
        var value=call;value["action"]=action;value["event"]=UUID().uuidString
        if let muted=muted { value["muted"]=muted }
        prefs.set(value,forKey:"elo.call.event")
    }
    private var pending: [String: Any]? {
        get { prefs.dictionary(forKey: "elo.call.pending") }
        set { prefs.set(newValue, forKey: "elo.call.pending") }
    }
    private override init() {
        super.init()
        rebuildProvider()
        // A previous process cannot retain the in-memory media session.
        if let call=pending, let raw=call["uuid"] as? String, let uuid=UUID(uuidString:raw) {
            provider.reportCall(with:uuid,endedAt:Date(),reason:.failed)
            pending=nil
        }
        if prefs.bool(forKey: "elo.call.enabled") { register() }
    }
    private func rebuildProvider() {
        let config = CXProviderConfiguration()
        config.supportsVideo = true
        config.maximumCallGroups = 1
        config.maximumCallsPerCallGroup = 1
        config.includesCallsInRecents = false
        config.supportedHandleTypes = [.generic]
        // Files are bundled from the same synthesized tones as Appearance previews.
        let tone = prefs.string(forKey: "elo.call.ringtone") ?? "classic"
        config.ringtoneSound = "elo_ring_\(tone).wav"
        provider = CXProvider(configuration: config)
        provider.setDelegate(self, queue: .main)
    }
    private func register() {
        if registry == nil {
            let value = PKPushRegistry(queue: .main)
            value.delegate = self
            registry = value
        }
        registry?.desiredPushTypes = [.voIP]
    }
    func configure(enabled: Bool, registration: String, endpoint: String, labels: [String: String], ringtone: String?) -> String? {
        prefs.set(enabled, forKey: "elo.call.enabled")
        prefs.set(registration, forKey: "elo.call.registration")
        prefs.set(endpoint, forKey: "elo.call.endpoint")
        for (key, value) in labels where value.count <= 160 { prefs.set(value, forKey: "elo.call.label." + key) }
        if let tone = ringtone, ["classic","chime","pulse","silent"].contains(tone), tone != prefs.string(forKey: "elo.call.ringtone") {
            prefs.set(tone,forKey:"elo.call.ringtone")
            if pending == nil { provider.invalidate(); rebuildProvider() }
        }
        if enabled { register() } else { disable() }
        return prefs.string(forKey: "elo.call.token")
    }
    func disable() {
        prefs.set(false, forKey: "elo.call.enabled")
        registry?.desiredPushTypes = []
        if let call = pending, let id = call["id"] as? String { end(id, reason: .remoteEnded) }
    }
    func pushRegistry(_ registry: PKPushRegistry, didUpdate pushCredentials: PKPushCredentials, for type: PKPushType) {
        prefs.set(pushCredentials.token.map { String(format: "%02x", $0) }.joined(), forKey: "elo.call.token")
    }
    func pushRegistry(_ registry: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) { prefs.removeObject(forKey: "elo.call.token") }
    func pushRegistry(_ registry: PKPushRegistry, didReceiveIncomingPushWith payload: PKPushPayload, for type: PKPushType, completion: @escaping () -> Void) {
        let data = payload.dictionaryPayload
        let id = data["elo_call_id"] as? String ?? ""
        let expires = Double(data["elo_expires"] as? String ?? "") ?? 0
        let target = data["elo_target"] as? String ?? ""
        let ticket = data["elo_ticket"] as? String ?? ""
        let now = Date().timeIntervalSince1970
        let valid = prefs.bool(forKey: "elo.call.enabled") && data["elo_registration"] as? String == prefs.string(forKey:"elo.call.registration")
            && id.range(of:"^[a-f0-9]{32}$",options:.regularExpression) != nil
            && ticket.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil
            && target.count <= 2048 && target.range(of:"^[A-Za-z0-9_-]{64,}$",options:.regularExpression) != nil
            && expires > now && expires <= now + 60 && pending == nil
        // Every VoIP delivery is reported promptly, including obsolete deliveries.
        // An obsolete/disabled ring is immediately ended; it never starts media.
        let uuid = UUID()
        let update = CXCallUpdate()
        update.remoteHandle = CXHandle(type:.generic,value:"elo.now")
        update.localizedCallerName = prefs.string(forKey:"elo.call.label.incoming") ?? "elo.now"
        update.hasVideo = data["elo_video"] as? String == "1"
        update.supportsHolding=false;update.supportsGrouping=false;update.supportsUngrouping=false;update.supportsDTMF=false
        if valid {
            pending = ["id":id,"uuid":uuid.uuidString,"expires":expires,"target":target,"ticket":ticket,
                "registration":data["elo_registration"] as? String ?? "","action":"ring","connected":false]
        }
        provider.reportNewIncomingCall(with:uuid,update:update) { [weak self] error in
            DispatchQueue.main.async {
                defer { completion() }
                guard let self = self else { return }
                if !valid || error != nil {
                    self.provider.reportCall(with:uuid,endedAt:Date(),reason:.failed)
                    if valid { self.pending=nil }
                } else { self.watch() }
            }
        }
    }
    func status() -> [String:Any]? { prefs.dictionary(forKey:"elo.call.event") ?? pending }
    func acknowledge(_ id:String, event:String?) {
        guard let value=prefs.dictionary(forKey:"elo.call.event"),value["id"] as? String == id,value["event"] as? String == event else { return }
        prefs.removeObject(forKey:"elo.call.event")
    }
    private func reject(_ id:String) {
        guard let call=pending,call["id"] as? String == id else { return }
        event(call,action:"decline")
        if let endpoint=prefs.string(forKey:"elo.call.endpoint"),let registration=call["registration"] as? String,
           let ticket=call["ticket"] as? String,let url=URL(string:endpoint+"v1/routes/\(registration)/calls/\(id)"),url.scheme=="https" {
            var request=URLRequest(url:url,timeoutInterval:3);request.httpMethod="DELETE"
            request.setValue("Bearer "+ticket,forHTTPHeaderField:"Authorization")
            session.dataTask(with:request).resume()
        }
        end(id)
    }
    func answering(_ id:String) {
        guard var call=pending,call["id"] as? String == id,call["action"] as? String == "ring",
            let raw=call["uuid"] as? String,let uuid=UUID(uuidString:raw) else { return }
        call["action"]="answer";pending=call
        CXCallController().request(CXTransaction(action:CXAnswerCallAction(call:uuid))) { [weak self] error in
            if error != nil { DispatchQueue.main.async { self?.end(id,reason:.failed) } }
        }
    }
    func connected(_ id:String) {
        guard var call=pending,call["id"] as? String == id else { return }
        call["connected"]=true;call["action"]="connected";pending=call
        answer?.fulfill();answer=nil
        timer?.invalidate();timer=nil
    }
    func end(_ id:String, reason:CXCallEndedReason = .remoteEnded) {
        guard let call=pending,call["id"] as? String == id,let raw=call["uuid"] as? String,let uuid=UUID(uuidString:raw) else { return }
        MainActor.assumeIsolated { NativeMedia.shared.stopAll() }
        answer?.fail();answer=nil
        provider.reportCall(with:uuid,endedAt:Date(),reason:reason)
        timer?.invalidate();timer=nil;pending=nil
    }
    func providerDidReset(_ provider:CXProvider) {
        // Rebuilding an idle provider after changing ringtone/background-call
        // settings must not terminate a foreground call it does not own.
        if let call=pending {
            MainActor.assumeIsolated { NativeMedia.shared.stopAll() }
            event(call,action:"decline")
        }
        timer?.invalidate();timer=nil;answer?.fail();answer=nil;pending=nil
    }
    func provider(_ provider:CXProvider,perform action:CXSetMutedCallAction) {
        guard let call=pending,call["uuid"] as? String == action.callUUID.uuidString,call["connected"] as? Bool == true else { action.fail();return }
        MainActor.assumeIsolated { NativeMedia.shared.peer?.muteMicrophone(action.isMuted) }
        event(call,action:"mute",muted:action.isMuted)
        action.fulfill()
    }
    func provider(_ provider:CXProvider,perform action:CXAnswerCallAction) {
        guard var call=pending,call["uuid"] as? String == action.callUUID.uuidString else { action.fail();return }
        if call["connected"] as? Bool == true { action.fulfill();return }
        do { try AVAudioSession.sharedInstance().setCategory(.playAndRecord,mode:.voiceChat,options:[.allowBluetooth,.defaultToSpeaker]) }
        catch { action.fail();return }
        call["action"]="answer";pending=call;answer=action
        // This explicit user action requests the app UI. Media stays stopped until
        // the ordinary profile-unlock flow and signed call admission both succeed.
        UIApplication.shared.open(URL(string:"elo://incoming-call")!,options:[:])
    }
    func provider(_ provider:CXProvider,perform action:CXEndCallAction) {
        if let id=pending?["id"] as? String { reject(id) }
        action.fulfill()
    }
    func provider(_ provider:CXProvider,timedOutPerforming action:CXAction) {
        if let id=pending?["id"] as? String { end(id,reason:.failed) }
    }
    private func watch() {
        timer?.invalidate()
        timer=Timer.scheduledTimer(withTimeInterval:2,repeats:true) { [weak self] _ in self?.check() }
        check()
    }
    private func check() {
        guard let call=pending,let id=call["id"] as? String else { return }
        if (call["expires"] as? Double ?? 0) <= Date().timeIntervalSince1970 { end(id,reason:.unanswered);return }
        if call["action"] as? String == "answer" { return }
        guard !checking,let endpoint=prefs.string(forKey:"elo.call.endpoint"),let registration=call["registration"] as? String,
              let ticket=call["ticket"] as? String,let url=URL(string:endpoint+"v1/routes/\(registration)/calls/\(id)"),url.scheme=="https" else { return }
        checking=true
        var request=URLRequest(url:url,timeoutInterval:3)
        request.setValue("Bearer "+ticket,forHTTPHeaderField:"Authorization")
        session.dataTask(with:request) { [weak self] data,response,_ in
            DispatchQueue.main.async {
                guard let self=self else { return };self.checking=false
                let code=(response as? HTTPURLResponse)?.statusCode
                guard self.pending?["id"] as? String == id,self.pending?["action"] as? String == "ring" else { return }
                if code==410 { self.end(id);return }
                if code==200,let data=data,data.count<=1024,let body=try? JSONSerialization.jsonObject(with:data) as? [String:Any],body["ringing"] as? Bool == false { self.end(id) }
            }
        }.resume()
    }
}
