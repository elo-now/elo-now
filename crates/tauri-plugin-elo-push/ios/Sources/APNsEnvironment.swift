import Foundation

/// The provisioning entitlement, not Debug/Release, selects APNs. App Store
/// builds have no embedded profile and use production. Read only our signed
/// bundle; this parser is not a verifier for externally supplied CMS documents.
enum APNsEnvironment {
    static let maximumProfileBytes = 1024 * 1024
    static let sandbox = read(Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"))

    private static func read(_ url: URL?) -> Bool {
        guard let url = url, let file = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? file.close() }
        guard let data = try? file.read(upToCount: maximumProfileBytes + 1) else { return false }
        return isSandbox(profile: data)
    }

    static func isSandbox(profile: Data?) -> Bool {
        guard let profile = profile, profile.count <= maximumProfileBytes,
            let start = profile.range(of: Data("<?xml".utf8)),
            let end = profile.range(of: Data("</plist>".utf8), in: start.lowerBound..<profile.endIndex),
            let plist = try? PropertyListSerialization.propertyList(from: profile.subdata(in: start.lowerBound..<end.upperBound), options: [], format: nil),
            let values = plist as? [String: Any], let entitlements = values["Entitlements"] as? [String: Any] else { return false }
        return entitlements["aps-environment"] as? String == "development"
    }
}
