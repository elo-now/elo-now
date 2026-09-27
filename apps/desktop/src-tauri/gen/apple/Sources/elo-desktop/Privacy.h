#import <Foundation/Foundation.h>

/// Called before Rust can open a profile, independently of optional plugins.
bool elo_prepare_private_storage(void);
void elo_protect_task_previews(void);
