// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

import Tauri
import UserNotifications

public class NotificationHandler: NSObject, NotificationHandlerProtocol {

  public weak var plugin: Plugin?

  var pendingAction: ReceivedNotification?

  private var notificationsMap = [String: Notification]()

  internal func saveNotification(_ key: String, _ notification: Notification) {
    notificationsMap.updateValue(notification, forKey: key)
  }

  public func requestPermissions(with completion: ((Bool, Error?) -> Void)? = nil) {
    let center = UNUserNotificationCenter.current()
    center.requestAuthorization(options: [.badge, .alert, .sound]) { (granted, error) in
      completion?(granted, error)
    }
  }

  public func checkPermissions(with completion: ((UNAuthorizationStatus) -> Void)? = nil) {
    let center = UNUserNotificationCenter.current()
    center.getNotificationSettings { settings in
      completion?(settings.authorizationStatus)
    }
  }

  public func willPresent(notification: UNNotification) -> UNNotificationPresentationOptions {
    let payload = notification.request.content.userInfo
    if payload["elo_wake"] != nil || payload["elo_registration"] != nil {
      persistPush(payload, opened: false)
      NotificationCenter.default.post(name: NSNotification.Name("elo.push.received"), object: nil, userInfo: payload)
      return []
    }
    let notificationData = toActiveNotification(notification.request)
    try? self.plugin?.trigger("notification", data: notificationData)

    if let options = notificationsMap[notification.request.identifier] {
      if options.silent ?? false {
        return UNNotificationPresentationOptions.init(rawValue: 0)
      }
    }

    return [
      .badge,
      .sound,
      .alert,
    ]
  }

  public func didReceive(response: UNNotificationResponse) {
    let payload = response.notification.request.content.userInfo
    if payload["elo_wake"] != nil || payload["elo_registration"] != nil {
      if response.actionIdentifier == UNNotificationDefaultActionIdentifier {
        persistPush(payload, opened: true)
        NotificationCenter.default.post(name: NSNotification.Name("elo.push.opened"), object: nil, userInfo: payload)
      }
      return
    }
    let originalNotificationRequest = response.notification.request
    let actionId = response.actionIdentifier

    var actionIdValue: String
    // We turn the two default actions (open/dismiss) into generic strings
    if actionId == UNNotificationDefaultActionIdentifier {
      actionIdValue = "tap"
    } else if actionId == UNNotificationDismissActionIdentifier {
      actionIdValue = "dismiss"
    } else {
      actionIdValue = actionId
    }

    var inputValue: String? = nil
    // If the type of action was for an input type, get the value
    if let inputType = response as? UNTextInputNotificationResponse {
      inputValue = inputType.userText
    }

    let action = ReceivedNotification(
      actionId: actionIdValue,
      inputValue: inputValue,
      notification: toActiveNotification(originalNotificationRequest)
    )
    // Keep the latest action until the web view has registered its listener.
    pendingAction = action
    try? self.plugin?.trigger("actionPerformed", data: action)
  }

  // This delegate can receive a cold-start tap before the Firebase plugin or web view exists.
  private func persistPush(_ data: [AnyHashable: Any], opened: Bool) {
    let prefs = UserDefaults.standard
    guard prefs.bool(forKey: "elo.push.enabled"),
          data["elo_registration"] as? String == prefs.string(forKey: "elo.push.registration") else { return }
    if let challenge = data["elo_challenge"] as? String,
       challenge.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil {
      prefs.set(challenge, forKey: "elo.push.challenge")
    } else if data["elo_wake"] as? String == "1", let target = data["elo_target"] as? String,
              target.count <= 2048, target.range(of: "^[A-Za-z0-9_-]{64,}$", options: .regularExpression) != nil {
      prefs.set(target, forKey: "elo.push.wake")
      if opened { prefs.set(target, forKey: "elo.push.opened") }
    }
  }

  func toActiveNotification(_ request: UNNotificationRequest) -> ActiveNotification {
    // Delivered requests outlive this process. Read their persisted OS content
    // without requiring an entry in the in-memory scheduling cache.
    let notificationRequest = notificationsMap[request.identifier]
    return ActiveNotification(
      id: Int(request.identifier) ?? -1,
      title: request.content.title,
      body: request.content.body,
      sound: notificationRequest?.sound ?? "",
      actionTypeId: request.content.categoryIdentifier,
      attachments: notificationRequest?.attachments
    )
  }

  func toPendingNotification(_ request: UNNotificationRequest) -> PendingNotification {
    return PendingNotification(
      id: Int(request.identifier) ?? -1,
      title: request.content.title,
      body: request.content.body
    )
  }
}

struct PendingNotification: Encodable {
  let id: Int
  let title: String
  let body: String
}

struct ActiveNotification: Encodable {
  let id: Int
  let title: String
  let body: String
  let sound: String
  let actionTypeId: String
  let attachments: [NotificationAttachment]?
}

struct ReceivedNotification: Encodable {
  let actionId: String
  let inputValue: String?
  let notification: ActiveNotification
}
