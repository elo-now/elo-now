#include "bindings/bindings.h"
#import "Privacy.h"

int main(int argc, char * argv[]) {
    @autoreleasepool {
        // Fail closed before profile creation if OS backup exclusion fails.
        if (!elo_prepare_private_storage()) return 1;
        elo_protect_task_previews();
        ffi::start_app();
    }
    return 0;
}
