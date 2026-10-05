#pragma once

// Presentation state only. Successful authorization comes from Rust after
// opening the protected profile; no UI message can authorize completion.
struct EloUnlockCoverState {
    bool prompt = false;
    bool biometricInactive = false;

    void reset() { prompt = false; biometricInactive = false; }
    void begin(bool active, bool covered) {
        reset();
        prompt = active && !covered;
    }
    bool resignNeedsCover() {
        if (prompt) {
            biometricInactive = true;
            return false;
        }
        biometricInactive = false;
        return true;
    }
    bool endNeedsCover(bool foregroundInactive) {
        prompt = false;
        // The still-locked login screen can remain visible while Rust verifies
        // the returned key. Background/reset never preserve this exception.
        return !(biometricInactive && foregroundInactive);
    }
    bool complete(bool foregroundInactive) {
        bool reveal = biometricInactive && foregroundInactive;
        reset();
        return reveal;
    }
};
