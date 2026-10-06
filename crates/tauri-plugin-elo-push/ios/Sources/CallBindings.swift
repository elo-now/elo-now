import Foundation
import Security

/// Contains only short-lived call delegations, never the profile password,
/// history keys or full device signing key. Not synced or included in backups.
enum CallBindings {
    private static let service = "now.elo.call-only.v1"
    static func command(_ request: [String: Any]) throws -> [String: Any] {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: "bindings",
            kSecAttrSynchronizable as String: false]
        switch request["op"] as? String {
        case "clear":
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw NativePeer.MediaError.unavailable }
            return [:]
        case "load":
            var read = query
            read[kSecReturnData as String] = true
            read[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(read as CFDictionary, &result)
            if status == errSecItemNotFound { return ["payload": NSNull()] }
            guard status == errSecSuccess, let data = result as? Data, data.count <= 2 * 1024 * 1024 else { throw NativePeer.MediaError.unavailable }
            return ["payload": data.base64EncodedString()]
        case "store":
            guard let payload = request["payload"] as? String, payload.utf8.count <= 3 * 1024 * 1024,
                  let data = Data(base64Encoded: payload), data.count <= 2 * 1024 * 1024 else { throw NativePeer.MediaError.invalid }
            let attributes: [String: Any] = [kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
            var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if status == errSecItemNotFound {
                var create = query
                for (key,value) in attributes { create[key] = value }
                status = SecItemAdd(create as CFDictionary, nil)
            }
            guard status == errSecSuccess else { throw NativePeer.MediaError.unavailable }
            return [:]
        default: throw NativePeer.MediaError.invalid
        }
    }
}
