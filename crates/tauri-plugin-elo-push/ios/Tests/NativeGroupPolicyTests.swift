import Foundation

@main struct NativeGroupPolicyTests {
    static func main() throws {
        let local = String(repeating: "a", count: 64)
        let peer = String(repeating: "b", count: 64)
        let other = String(repeating: "c", count: 64)
        let key = String(repeating: "1", count: 64)
        let rotated = String(repeating: "2", count: 64)
        var policy = NativeGroupPolicy()
        try policy.accept(epoch: 2, key: key, participants: [local, peer], credential: local)
        // Retrying a room after disconnect may preserve the exact signed epoch.
        try policy.accept(epoch: 2, key: key, participants: [peer, local], credential: local)
        func reject(_ epoch: UInt64, _ nextKey: String, _ members: [String], _ credential: String) {
            do {
                try policy.accept(epoch: epoch, key: nextKey, participants: members, credential: credential)
                fatalError("An invalid group epoch was accepted")
            } catch {}
            assert(policy.epoch == 2 && policy.members == Set([local, peer]) && policy.credential == local)
        }
        reject(1, key, [local, peer], local)
        reject(2, rotated, [local, peer], local)
        reject(2, key, [local, other], local)
        reject(2, key, [local, peer], peer)
        reject(3, key, [local, peer], local)
        reject(3, rotated, [peer], local)
        reject(3, rotated, [local, local], local)
        reject(3, "not-a-key", [local, peer], local)
        try policy.accept(epoch: 3, key: rotated, participants: [local, other], credential: local)
        assert(policy.epoch == 3 && policy.members == Set([local, other]))
        print("PASS: exact epoch retry, replay rejection, membership/local/key binding, required rotation and atomic rejection")
    }
}
