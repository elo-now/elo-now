import Tauri
import UIKit

private struct CopyArgs: Decodable { let text: String }

final class EloPrivacyPlugin: Plugin {
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
