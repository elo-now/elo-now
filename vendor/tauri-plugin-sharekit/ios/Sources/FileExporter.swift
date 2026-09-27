import Foundation
import UIKit

struct ExportFileOptions: Decodable {
  let url: String
  let filename: String
}

/// Retains the real export contents until the document provider finishes.
/// Only explicit picker cancellation resolves as an unsaved export.
final class FileExporter: NSObject, UIDocumentPickerDelegate, UIAdaptivePresentationControllerDelegate {
  private let directory: URL
  let picker: UIDocumentPickerViewController
  private var completion: ((Bool) -> Void)?

  init(source: URL, filename: String, completion: @escaping (Bool) -> Void) throws {
    let files = FileManager.default
    directory = files.temporaryDirectory.appendingPathComponent("elo-export-\(UUID().uuidString)", isDirectory: true)
    try files.createDirectory(at: directory, withIntermediateDirectories: false,
                              attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
    let destination = directory.appendingPathComponent(filename, isDirectory: false)
    do {
      try files.copyItem(at: source, to: destination)
      try files.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                              ofItemAtPath: destination.path)
    } catch {
      try? files.removeItem(at: directory)
      throw error
    }
    picker = UIDocumentPickerViewController(forExporting: [destination], asCopy: true)
    self.completion = completion
    super.init()
    picker.delegate = self
    picker.presentationController?.delegate = self
  }

  deinit {
    try? FileManager.default.removeItem(at: directory)
  }

  private func finish(saved: Bool) {
    guard let callback = completion else { return }
    completion = nil
    callback(saved)
  }

  func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    finish(saved: true)
  }

  func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
    finish(saved: false)
  }

  func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
    finish(saved: false)
  }
}
