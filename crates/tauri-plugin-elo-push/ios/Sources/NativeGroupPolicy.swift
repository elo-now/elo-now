import Foundation
import CryptoKit

/// Keep the last admitted epoch across room reconnects, without retaining its key.
struct NativeGroupPolicy {
    private(set) var epoch: UInt64 = 0
    private(set) var members = Set<String>()
    private(set) var credential = ""
    private var digest: SHA256.Digest?
    enum Failure: Error { case invalid }

    mutating func accept(epoch: UInt64, key: String, participants: [String], credential: String) throws {
        let members = Set(participants)
        guard epoch > 0, epoch >= self.epoch, key.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
            (1...128).contains(participants.count), members.count == participants.count, members.contains(credential),
            members.allSatisfy({ $0.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil }) else { throw Failure.invalid }
        let digest = SHA256.hash(data: Data(key.utf8))
        if epoch == self.epoch {
            guard self.members == members, self.credential == credential, self.digest == digest else { throw Failure.invalid }
        } else if self.epoch != 0 {
            guard self.digest != digest else { throw Failure.invalid }
        }
        self.epoch = epoch; self.members = members; self.credential = credential; self.digest = digest
    }
}
