import Foundation

/// Native-only route IDs; provider tokens and host capabilities never enter the web view.
enum PushRegistrations {
    static let limit = 32
    static func all(_ prefs: UserDefaults) -> Set<String> {
        if let values = prefs.stringArray(forKey: "elo.push.registrations") { return Set(values) }
        return Set(prefs.string(forKey: "elo.push.registration").map { [$0] } ?? [])
    }
    static func contains(_ registration: String?, prefs: UserDefaults) -> Bool {
        guard let registration = registration else { return false }
        return all(prefs).contains(registration)
    }
    static func add(_ registration: String, prefs: UserDefaults) -> Bool {
        var values = all(prefs)
        guard values.contains(registration) || values.count < limit else { return false }
        if let legacy = prefs.string(forKey: "elo.push.registration") {
            if let challenge = prefs.string(forKey: "elo.push.challenge") {
                prefs.set(challenge, forKey: challengeKey(legacy))
                prefs.removeObject(forKey: "elo.push.challenge")
            }
            for key in ["wake", "opened"] where prefs.string(forKey: "elo.push.\(key)") != nil {
                prefs.set(legacy, forKey: "elo.push.\(key).registration")
            }
        }
        values.insert(registration)
        prefs.set(Array(values).sorted(), forKey: "elo.push.registrations")
        prefs.removeObject(forKey: "elo.push.registration")
        return true
    }
    static func remove(_ registration: String, prefs: UserDefaults) {
        let targets = ["wake", "opened"].filter { targetRegistration($0, prefs: prefs) == registration }
        if prefs.string(forKey: "elo.push.registration") == registration {
            prefs.removeObject(forKey: "elo.push.challenge")
        }
        var values = all(prefs)
        values.remove(registration)
        prefs.set(Array(values).sorted(), forKey: "elo.push.registrations")
        prefs.removeObject(forKey: "elo.push.registration")
        prefs.removeObject(forKey: challengeKey(registration))
        for key in targets {
            prefs.removeObject(forKey: "elo.push.\(key)")
            prefs.removeObject(forKey: "elo.push.\(key).registration")
        }
    }
    static func targetRegistration(_ key: String, prefs: UserDefaults) -> String? {
        prefs.string(forKey: "elo.push.\(key).registration") ?? prefs.string(forKey: "elo.push.registration")
    }
    static func challengeKey(_ registration: String) -> String { "elo.push.challenge.\(registration)" }
}
