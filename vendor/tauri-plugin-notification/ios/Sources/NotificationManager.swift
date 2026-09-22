// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

import Foundation
import UserNotifications

@objc public protocol NotificationHandlerProtocol {
  func willPresent(notification: UNNotification) -> UNNotificationPresentationOptions
  func didReceive(response: UNNotificationResponse)
}

@objc public class NotificationManager: NSObject, UNUserNotificationCenterDelegate {
  public weak var notificationHandler: NotificationHandlerProtocol?

  override init() {
    super.init()
    let center = UNUserNotificationCenter.current()
    center.delegate = self
  }

  public func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    willPresent notification: UNNotification,
    withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
  ) {
    var presentationOptions: UNNotificationPresentationOptions? = nil

    if handles(notification) {
      presentationOptions = notificationHandler?.willPresent(notification: notification)
    }

    completionHandler(presentationOptions ?? [])
  }

  public func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    didReceive response: UNNotificationResponse,
    withCompletionHandler completionHandler: @escaping () -> Void
  ) {
    if handles(response.notification) {
      notificationHandler?.didReceive(response: response)
    }

    completionHandler()
  }

  // The upstream plugin handles only local notifications. elo's FCM route
  // challenges and cold-start taps use this same delegate; their handler checks
  // the active registration before persisting any opaque target or challenge.
  private func handles(_ notification: UNNotification) -> Bool {
    notification.request.trigger?.isKind(of: UNPushNotificationTrigger.self) != true
      || notification.request.content.userInfo["elo_registration"] is String
  }
}
