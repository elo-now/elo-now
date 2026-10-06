import Foundation

@main struct APNsEnvironmentTests {
    static func main() {
        func profile(_ entitlement: Any) -> Data {
            let plist = try! PropertyListSerialization.data(fromPropertyList: ["Entitlements": ["aps-environment": entitlement]], format: .xml, options: 0)
            return Data([0x30, 0x82, 0x00, 0x01]) + plist + Data([0xff, 0x00])
        }
        assert(APNsEnvironment.isSandbox(profile: profile("development")))
        assert(!APNsEnvironment.isSandbox(profile: profile("production")))
        assert(!APNsEnvironment.isSandbox(profile: nil))
        assert(!APNsEnvironment.isSandbox(profile: Data()))
        assert(!APNsEnvironment.isSandbox(profile: profile(true)))
        assert(!APNsEnvironment.isSandbox(profile: profile("sandbox")))
        assert(!APNsEnvironment.isSandbox(profile: Data("<?xml invalid </plist>".utf8)))
        let tooLarge = profile("development") + Data(repeating: 0, count: APNsEnvironment.maximumProfileBytes)
        assert(!APNsEnvironment.isSandbox(profile: tooLarge))
        print("PASS: development entitlement, production/App Store default, invalid/bounded provisioning data")
    }
}
