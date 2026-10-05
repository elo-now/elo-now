#include "../../apps/desktop/src-tauri/gen/apple/Sources/elo-desktop/UnlockCoverState.h"
#include <cassert>

int main() {
    EloUnlockCoverState state;
    // Ordinary app switching never acquires the login exception.
    assert(state.resignNeedsCover());
    assert(!state.complete(true));

    // The locked login screen stays visible after Keychain returns. Native
    // profile verification must still complete before opening the profile.
    state.begin(true, false);
    assert(!state.resignNeedsCover());
    assert(!state.endNeedsCover(true));
    assert(state.complete(true));
    assert(!state.complete(true));
    assert(state.resignNeedsCover());

    // Cancellation, unrelated activation, and backgrounding all revoke the
    // episode. A late unlock result must not uncover the task preview.
    state.begin(true, false);
    assert(!state.resignNeedsCover());
    assert(!state.endNeedsCover(true));
    state.reset();
    assert(state.endNeedsCover(true));
    assert(!state.complete(true));
    assert(state.resignNeedsCover());

    // Starting while covered or already inactive cannot authorize a reveal.
    state.begin(true, true);
    assert(state.endNeedsCover(true));
    assert(state.resignNeedsCover());
    assert(!state.complete(true));
    state.begin(false, false);
    assert(state.endNeedsCover(true));
    assert(state.resignNeedsCover());
    assert(!state.complete(true));

    // A denied completion consumes the episode rather than preserving a
    // permission that could unexpectedly become valid after resuming.
    state.begin(true, false);
    assert(!state.resignNeedsCover());
    assert(state.endNeedsCover(false));
    assert(!state.complete(false));
    assert(!state.complete(true));

    // A second unrelated resignation after Keychain returns restores privacy.
    state.begin(true, false);
    assert(!state.resignNeedsCover());
    assert(!state.endNeedsCover(true));
    assert(state.resignNeedsCover());
    assert(!state.complete(true));
}
