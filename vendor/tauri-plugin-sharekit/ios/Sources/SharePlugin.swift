import LocalAuthentication
import SwiftRs
import Tauri
import UIKit
import WebKit
import SwiftUI
import UIKit
import Foundation

struct SharePosition: Decodable {
  let x: Double
  let y: Double
  let preferredEdge: String?  // ignored on iOS
}

struct ShareOptions: Decodable {
  let text: String
  let position: SharePosition?
}

struct ShareFileOptions: Decodable {
  let url: String
  let title: String?
  let position: SharePosition?
}

class SharePlugin: Plugin {
  var webview: WKWebView!
  private var fileExporter: FileExporter?
  public override func load(webview: WKWebView) {
    self.webview = webview
  }

  @objc func exportFile(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ExportFileOptions.self)
    DispatchQueue.main.async {
      guard let source = URL(string: args.url), source.isFileURL,
            !args.filename.isEmpty, args.filename != ".", args.filename != "..",
            !args.filename.contains("/"), !args.filename.contains("\\"),
            self.fileExporter == nil,
            let presenter = self.manager.viewController,
            presenter.viewIfLoaded?.window?.windowScene?.activationState == .foregroundActive,
            presenter.presentedViewController == nil else {
        invoke.reject("file_export_failed")
        return
      }
      do {
        let exporter = try FileExporter(source: source, filename: args.filename) { [weak self] saved in
          self?.fileExporter = nil
          invoke.resolve(["saved": saved])
        }
        self.fileExporter = exporter
        presenter.present(exporter.picker, animated: true)
      } catch {
        invoke.reject("file_export_failed")
      }
    }
  }

  @objc func shareText(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ShareOptions.self)

    DispatchQueue.main.async {
      let activityViewController = UIActivityViewController(activityItems: [args.text], applicationActivities: nil)

      // Display as popover on iPad as required by Apple
      let posX = args.position?.x ?? Double(self.webview.bounds.midX)
      let posY = args.position?.y ?? Double(self.webview.bounds.midY)
      activityViewController.popoverPresentationController?.sourceView = self.webview
      activityViewController.popoverPresentationController?.sourceRect = CGRect(
        x: posX,
        y: posY,
        width: 0.0,
        height: 0.0
      )

      activityViewController.completionWithItemsHandler = { _, completed, _, error in
        if let error = error {
          invoke.reject(error.localizedDescription)
        } else if completed {
          invoke.resolve()
        } else {
          invoke.reject("Share cancelled")
        }
      }

      self.manager.viewController?.present(activityViewController, animated: true, completion: nil)
    }
  }

  @objc func shareFile(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ShareFileOptions.self)
    
    DispatchQueue.main.async {
      // Convert URL string to URL object
      guard let fileUrl = URL(string: args.url), fileUrl.isFileURL,
            let presenter = self.manager.viewController,
            presenter.viewIfLoaded?.window?.windowScene?.activationState == .foregroundActive,
            presenter.presentedViewController == nil else {
        invoke.reject("file_export_failed")
        return
      }

      // The native caller retains this private file until completion. Avoid
      // leaving another plaintext copy in the root of the app's temp folder.
      let activityItems: [Any] = [fileUrl]

      let activityViewController = UIActivityViewController(
        activityItems: activityItems,
        applicationActivities: nil
      )
      
      // Display as popover on iPad as required by Apple
      let posX = args.position?.x ?? Double(self.webview.bounds.midX)
      let posY = args.position?.y ?? Double(self.webview.bounds.midY)
      activityViewController.popoverPresentationController?.sourceView = self.webview
      activityViewController.popoverPresentationController?.sourceRect = CGRect(
        x: posX,
        y: posY,
        width: 0.0,
        height: 0.0
      )

      activityViewController.completionWithItemsHandler = { _, completed, _, error in
        if let error = error {
          invoke.reject(error.localizedDescription)
        } else if completed {
          invoke.resolve()
        } else {
          invoke.reject("Share cancelled")
        }
      }

      presenter.present(activityViewController, animated: true, completion: nil)
    }
  }
}

@_cdecl("init_plugin_share")
func initPlugin() -> Plugin {
  return SharePlugin()
}
