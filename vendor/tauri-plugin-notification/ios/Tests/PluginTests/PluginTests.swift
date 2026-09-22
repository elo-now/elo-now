// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0 OR MIT

import XCTest
import UserNotifications
@testable import tauri_plugin_notification

final class NotificationHandlerTests: XCTestCase {
  func testDeliveredRequestSurvivesAnEmptyProcessCache() throws {
    let content = UNMutableNotificationContent()
    content.title = "elo.now"
    content.body = "You have a reminder."
    let request = UNNotificationRequest(identifier: "731", content: content, trigger: nil)
    // A fresh handler models app restart, when the OS still has delivered notices.
    let handler = NotificationHandler()
    let delivered = handler.toActiveNotification(request)
    XCTAssertEqual(delivered.id, 731)
    XCTAssertEqual(delivered.title, content.title)
    XCTAssertEqual(delivered.body, content.body)
    XCTAssertNil(delivered.attachments)
    XCTAssertNil(handler.pendingAction)
  }
}
