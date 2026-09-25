import CryptoKit
import DeviceCheck
import Foundation
import Security

/// Signs the token read from PushKit's native callback, never a renderer token.
/// Apple attests a key once; fresh server challenges use assertions thereafter.
@MainActor enum VoipOwnership {
    private struct Key: Codable {
        var id: String
        var nonce: String
        var attestation: String?
    }
    enum Failure: Error { case unavailable, changed, invalid }
    private static var pending = false
    private static func hex(_ value: String, _ count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func proof(identity: String, nonce: String) async throws -> [String: String] {
        guard !pending, hex(identity, 64), hex(nonce, 64), DCAppAttestService.shared.isSupported else {
            throw Failure.unavailable
        }
        pending = true
        defer { pending = false }
        let prefs = UserDefaults.standard
        guard let route = prefs.string(forKey: "elo.call.registration"), hex(route, 32),
              let rawEndpoint = prefs.string(forKey: "elo.call.endpoint"),
              let url = URL(string: rawEndpoint), url.scheme == "https",
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              let token = prefs.string(forKey: "elo.call.token"),
              token.count >= 32, token.count <= 512, hex(token, token.count) else { throw Failure.invalid }
        let endpoint = rawEndpoint.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let context = SHA256.hash(data: Data((endpoint + "\n" + identity).utf8)).map { String(format: "%02x", $0) }.joined()
        let slot = "elo.voip.attest." + context
        var saved: Key?
        if let data = prefs.data(forKey: slot), data.count <= 32768 {
            saved = try? JSONDecoder().decode(Key.self, from: data)
        }
        if saved == nil {
            let id = try await DCAppAttestService.shared.generateKey()
            var random = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else { throw Failure.unavailable }
            saved = Key(id: id, nonce: random.map { String(format: "%02x", $0) }.joined(), attestation: nil)
            prefs.set(try JSONEncoder().encode(saved!), forKey: slot)
        }
        guard var key = saved, key.id.count == 44, hex(key.nonce, 64) else { throw Failure.invalid }
        do {
            if key.attestation == nil {
                let enrollment = "elo.now/voip-key/v1\n\(identity)\n\(key.nonce)"
                let attestation = try await DCAppAttestService.shared.attestKey(key.id,
                    clientDataHash: Data(SHA256.hash(data: Data(enrollment.utf8))))
                key.attestation = attestation.base64EncodedString()
                prefs.set(try JSONEncoder().encode(key), forKey: slot)
            }
            let payload = "elo.now/voip-ownership/v1\n\(endpoint)\n\(route)\n\(identity)\n\(key.id)\n\(token)\n\(nonce)"
            let assertion = try await DCAppAttestService.shared.generateAssertion(key.id,
                clientDataHash: Data(SHA256.hash(data: Data(payload.utf8))))
            guard prefs.string(forKey: "elo.call.token") == token,
                prefs.string(forKey: "elo.call.registration") == route,
                prefs.string(forKey: "elo.call.endpoint") == rawEndpoint else { throw Failure.changed }
            return ["token": token, "nonce": nonce, "key_id": key.id, "enrollment_nonce": key.nonce,
                    "attestation": key.attestation!, "assertion": assertion.base64EncodedString()]
        } catch {
            let native = error as NSError
            if native.domain == DCErrorDomain && native.code == DCError.Code.invalidKey.rawValue {
                prefs.removeObject(forKey: slot)
            }
            throw error
        }
    }
}
