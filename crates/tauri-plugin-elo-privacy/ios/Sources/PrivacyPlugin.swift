import Tauri
import UIKit
import WebKit

private struct CopyArgs: Decodable { let text: String }

// This bridge controls presentation only and accepts no profile data or commands.
private final class AppearanceHandler: NSObject, WKScriptMessageHandler {
    weak var owner: EloPrivacyPlugin?
    init(_ owner: EloPrivacyPlugin) { self.owner = owner }
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              let preference = message.body as? String,
              ["dark", "light", "auto"].contains(preference) else { return }
        owner?.applyAppearance(preference)
    }
}

// Local diagnostics accept one fixed lifecycle marker, never renderer data.
private final class UnlockFrameHandler: NSObject, WKScriptMessageHandler {
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              message.body as? String == "frame",
              Bundle.main.object(forInfoDictionaryKey: "EloUnlockTimingEnabled") as? Bool == true else { return }
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Notification.Name("elo.privacy.unlockFrame"), object: nil)
        }
    }
}

final class EloPrivacyPlugin: Plugin {
    private weak var appearanceWebView: WKWebView?

    override func load(webview: WKWebView) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.appearanceWebView = webview
            self.applyAppearance(UserDefaults.standard.string(forKey: "elo.appearance") ?? "dark")
            let controller = webview.configuration.userContentController
            controller.removeScriptMessageHandler(forName: "eloAppearance")
            controller.add(AppearanceHandler(self), name: "eloAppearance")
            controller.removeScriptMessageHandler(forName: "eloUnlockFrame")
            let timingEnabled = Bundle.main.object(forInfoDictionaryKey: "EloUnlockTimingEnabled") as? Bool == true
            if timingEnabled {
                controller.add(UnlockFrameHandler(), name: "eloUnlockFrame")
            }
            var script = """
            (() => {
            if (location.href === "about:blank") return;
            window.eloAppearance = {
              ...window.eloAppearance,
              setPreference(preference) {
                if (["dark", "light", "auto"].includes(preference)) {
                  window.webkit.messageHandlers.eloAppearance.postMessage(preference);
                }
              }
            };
            // Migrate the existing WebView preference on the first updated launch.
            try {
              const saved = localStorage.getItem("elo.appearance");
              window.eloAppearance.setPreference(saved === "auto" || saved === "light" ? saved : "dark");
            } catch { window.eloAppearance.setPreference("dark"); }
            })();
            """
            if timingEnabled {
                script += """

                (() => {
                if (location.href === "about:blank") return;
                window.eloAppearance = {
                  ...window.eloAppearance,
                  recordUnlockFrame() {
                    window.webkit.messageHandlers.eloUnlockFrame.postMessage("frame");
                  }
                };
                })();
                """
            }
            controller.addUserScript(WKUserScript(source: script, injectionTime: .atDocumentStart, forMainFrameOnly: true))
            // Plugin loading may finish after the initial document has started.
            webview.evaluateJavaScript(script, completionHandler: nil)
        }
    }

    fileprivate func applyAppearance(_ preference: String) {
        let mode = ["dark", "light", "auto"].contains(preference) ? preference : "dark"
        UserDefaults.standard.set(mode, forKey: "elo.appearance")
        guard let webview = appearanceWebView else { return }
        webview.overrideUserInterfaceStyle = mode == "auto" ? .unspecified : (mode == "light" ? .light : .dark)
        webview.isOpaque = false
        let background = UIColor(named: "LaunchBackground") ?? .systemBackground
        webview.backgroundColor = background
        webview.scrollView.backgroundColor = background
    }

    // Rust authorizes this only for a biometric unlock of the locked profile.
    // Acknowledge on the main queue after the cover observer has handled it.
    @objc func beginUnlockPrompt(_ invoke: Invoke) {
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Notification.Name("elo.privacy.unlockPrompt.begin"), object: nil)
            invoke.resolve()
        }
    }

    @objc func endUnlockPrompt(_ invoke: Invoke) {
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Notification.Name("elo.privacy.unlockPrompt.end"), object: nil)
            invoke.resolve()
        }
    }

    @objc func completeBiometricUnlock(_ invoke: Invoke) {
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Notification.Name("elo.privacy.unlockPrompt.complete"), object: nil)
            invoke.resolve()
        }
    }

    @objc func resetUnlockPrompt(_ invoke: Invoke) {
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: Notification.Name("elo.privacy.unlockPrompt.reset"), object: nil)
            invoke.resolve()
        }
    }

    @objc func copyRecoveryCode(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(CopyArgs.self)
        guard !args.text.isEmpty, args.text.utf8.count <= 2048, !args.text.contains("\0") else {
            invoke.reject("Could not copy the recovery code."); return
        }
        DispatchQueue.main.async {
            UIPasteboard.general.setItems([["public.utf8-plain-text": args.text]], options: [
                .localOnly: true, .expirationDate: Date().addingTimeInterval(60)
            ])
            invoke.resolve()
        }
    }
    @objc func openUpdate(_ invoke: Invoke) {
        DispatchQueue.main.async {
            UIApplication.shared.open(URL(string: "https://apps.apple.com/app/id6814766127")!, options: [:]) { opened in
                if opened { invoke.resolve() }
                else { invoke.reject("Could not open the download page.") }
            }
        }
    }
}

@_cdecl("init_plugin_elo_privacy")
public func initPluginEloPrivacy() -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(EloPrivacyPlugin()).toOpaque()
}
