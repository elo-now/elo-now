import Foundation
import GoogleUtilities_NSData
import FirebaseCore
import FirebaseCrashlytics

/// Receives only the application's bounded, allowlisted diagnostic vocabulary.
/// Never pass NSError.userInfo, URLs, request bodies or profile data here.
public enum EloDiagnostics {
    private static let lock = NSRecursiveLock()
    private static var enabled = false

    public static func command(_ body: [String: Any]) {
        if !Thread.isMainThread {
            DispatchQueue.main.async { command(body) }
            return
        }
        lock.lock(); defer { lock.unlock() }
        if body["op"] as? String == "configure" {
            #if os(macOS)
            UserDefaults.standard.register(defaults: ["NSApplicationCrashOnExceptions": true])
            #endif
            guard !GULNSDataZlibErrorDomain.isEmpty else { return }
            if FirebaseApp.app() == nil,
               Bundle.main.path(forResource: "GoogleService-Info", ofType: "plist") != nil {
                FirebaseApp.configure()
            }
            guard FirebaseApp.app() != nil else { return }
            let sdk = Crashlytics.crashlytics()
            // Explicit sending avoids a persisted SDK override enabling uploads
            // before the next build has applied its beta policy and user choice.
            sdk.setCrashlyticsCollectionEnabled(false)
            enabled = body["enabled"] as? Bool == true
            if enabled {
                sdk.setCustomValue("beta", forKey: "distribution")
                sdk.setUserID(body["installation"] as? String ?? "")
                sdk.sendUnsentReports()
            } else {
                sdk.setUserID("")
                sdk.deleteUnsentReports()
            }
            return
        }
        guard enabled, FirebaseApp.app() != nil,
              let code = body["code"] as? String, code.utf8.count <= 100,
              code.range(of: "^[A-Za-z0-9_.:-]+$", options: .regularExpression) != nil else { return }
        let sdk = Crashlytics.crashlytics()
        let source = body["source"] as? String ?? "unknown"
        let elapsed = body["elapsed_ms"] as? NSNumber ?? 0
        sdk.log("\(source):\(code) duration_ms=\(elapsed)")
        if body["kind"] as? String == "error" {
            let error = ExceptionModel(name: "elo.\(source).\(code)", reason: code)
            sdk.record(exceptionModel: error)
        }
    }

    public static func mediaFailure(_ error: Error, stage: String) {
        lock.lock(); defer { lock.unlock() }
        guard enabled, FirebaseApp.app() != nil else { return }
        let native = error as NSError
        // Domains and error text can be supplied by a remote endpoint. Only
        // trusted SDK domain names and the numeric code cross this boundary.
        let domain: String
        switch native.domain {
        case NSURLErrorDomain: domain = "url"
        case NSOSStatusErrorDomain: domain = "osstatus"
        case "LiveKit.LiveKitError", "LiveKitError": domain = "livekit"
        default: domain = "native"
        }
        let sdk = Crashlytics.crashlytics()
        sdk.setCustomValue(native.code, forKey: "native_error_code")
        sdk.setCustomValue(domain, forKey: "native_error_domain")
        command(["kind": "error", "source": "media", "code": stage])
    }
}

@_cdecl("elo_diagnostics_command")
public func eloDiagnosticsCommand(_ bytes: UnsafePointer<CChar>?) {
    guard let bytes else { return }
    let data = Data(String(cString: bytes).utf8)
    guard data.count <= 2048,
          let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return }
    EloDiagnostics.command(body)
}
