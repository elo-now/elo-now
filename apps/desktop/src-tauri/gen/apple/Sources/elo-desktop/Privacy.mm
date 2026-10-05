#import "Privacy.h"
#include "UnlockCoverState.h"
#import <UIKit/UIKit.h>

// Local diagnostic builds opt in through an otherwise absent Info.plist key.
// Only fixed lifecycle labels and monotonic milliseconds enter this cache file.
typedef NS_ENUM(NSUInteger, EloCoverTimingEvent) {
    EloCoverTimingResignActive,
    EloCoverTimingAdded,
    EloCoverTimingBecomeActive,
    EloCoverTimingRemoved,
    EloCoverTimingPromptBegin,
    EloCoverTimingPromptEnd,
    EloCoverTimingSkipped,
    EloCoverTimingBackground,
    EloCoverTimingUnlockRevealed,
    EloCoverTimingUnlockFrame,
};

static void elo_record_cover_timing(EloCoverTimingEvent event) {
    if (![NSBundle.mainBundle.infoDictionary[@"EloUnlockTimingEnabled"] boolValue]) return;
    NSString *name;
    switch (event) {
        case EloCoverTimingResignActive: name = @"resign_active"; break;
        case EloCoverTimingAdded: name = @"cover_added"; break;
        case EloCoverTimingBecomeActive: name = @"become_active"; break;
        case EloCoverTimingRemoved: name = @"cover_removed"; break;
        case EloCoverTimingPromptBegin: name = @"prompt_begin"; break;
        case EloCoverTimingPromptEnd: name = @"prompt_end"; break;
        case EloCoverTimingSkipped: name = @"cover_skipped"; break;
        case EloCoverTimingBackground: name = @"background"; break;
        case EloCoverTimingUnlockRevealed: name = @"unlock_revealed"; break;
        case EloCoverTimingUnlockFrame: name = @"unlock_frame"; break;
        default: return;
    }
    NSData *line = [[NSString stringWithFormat:@"elo-cover event=%@ uptime_ms=%.0f\n",
        name, NSProcessInfo.processInfo.systemUptime * 1000] dataUsingEncoding:NSUTF8StringEncoding];
    static dispatch_queue_t writer;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        writer = dispatch_queue_create("now.elo.unlock-cover-timing", DISPATCH_QUEUE_SERIAL);
    });
    // File I/O must not hold up the main queue or the removal of the cover.
    dispatch_async(writer, ^{
        @autoreleasepool {
            NSFileManager *manager = NSFileManager.defaultManager;
            NSURL *cache = [manager URLForDirectory:NSCachesDirectory inDomain:NSUserDomainMask
                appropriateForURL:nil create:YES error:nil];
            if (!cache) return;
            NSURL *file = [cache URLByAppendingPathComponent:@"elo-unlock-cover-timing.log"];
            NSDictionary *attributes = [manager attributesOfItemAtPath:file.path error:nil];
            if (!attributes || [attributes[NSFileSize] unsignedLongLongValue] + line.length > 64 * 1024) {
                [line writeToURL:file options:NSDataWritingAtomic error:nil];
                return;
            }
            NSFileHandle *handle = [NSFileHandle fileHandleForWritingToURL:file error:nil];
            if (!handle) return;
            if ([handle seekToEndReturningOffset:NULL error:nil]) [handle writeData:line error:nil];
            [handle closeAndReturnError:nil];
        }
    });
}

bool elo_prepare_private_storage(void) {
    NSFileManager *manager = NSFileManager.defaultManager;
    NSError *error = nil;
    NSURL *support = [manager URLForDirectory:NSApplicationSupportDirectory
        inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:&error];
    NSURL *documents = [manager URLForDirectory:NSDocumentDirectory
        inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:&error];
    NSURL *library = [manager URLForDirectory:NSLibraryDirectory
        inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:&error];
    if (!support || !documents || !library) return false;
    NSURL *marker = [support URLByAppendingPathComponent:@".elo-private-storage-v1"];
    BOOL migrate = ![manager fileExistsAtPath:marker.path];
    NSDictionary *protection = @{ NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication };
    for (NSURL *root in @[support, documents, [library URLByAppendingPathComponent:@"Preferences" isDirectory:YES]]) {
        if (![manager createDirectoryAtURL:root withIntermediateDirectories:YES attributes:protection error:&error]
            || ![root setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:&error]
            || ![manager setAttributes:protection ofItemAtPath:root.path error:&error]) return false;
        // Only the first upgrade scans old files. New children inherit their
        // directory's protection; every launch reapplies backup exclusion.
        if (migrate) {
            __block BOOL failed = NO;
            NSDirectoryEnumerator *entries = [manager enumeratorAtURL:root
                includingPropertiesForKeys:@[NSURLIsSymbolicLinkKey] options:0
                errorHandler:^BOOL(NSURL *url, NSError *failure) { failed = YES; return NO; }];
            if (!entries) return false;
            for (NSURL *entry in entries) {
                NSNumber *symlink = nil;
                if (![entry getResourceValue:&symlink forKey:NSURLIsSymbolicLinkKey error:&error]) return false;
                if (symlink.boolValue) { [entries skipDescendants]; continue; }
                if (![manager setAttributes:protection ofItemAtPath:entry.path error:&error]) return false;
            }
            if (failed) return false;
        }
    }
    if (migrate && ![NSData.data writeToURL:marker options:NSDataWritingAtomic error:&error]) return false;
    return true;
}

void elo_protect_task_previews(void) {
    static NSMutableArray<UIView *> *covers;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        covers = [NSMutableArray new];
        NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
        // The exception is limited to the Keychain prompt while Rust holds a
        // locked profile. Open chats keep the original inactive-screen cover.
        __block EloUnlockCoverState unlockState;
        void (^addCover)(void) = ^{
            if (covers.count) return;
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                if (![scene isKindOfClass:UIWindowScene.class]) continue;
                for (UIWindow *window in ((UIWindowScene *)scene).windows) {
                    if (!window.isKeyWindow) continue;
                    UIView *cover = [[UIView alloc] initWithFrame:window.bounds];
                    // The launch storyboard is always dark; task previews follow
                    // the saved app preference rather than only the system theme.
                    NSString *appearance = [NSUserDefaults.standardUserDefaults stringForKey:@"elo.appearance"];
                    cover.overrideUserInterfaceStyle = [appearance isEqualToString:@"auto"]
                        ? UIUserInterfaceStyleUnspecified
                        : ([appearance isEqualToString:@"light"] ? UIUserInterfaceStyleLight : UIUserInterfaceStyleDark);
                    cover.backgroundColor = [UIColor colorNamed:@"LaunchBackground"] ?: UIColor.systemBackgroundColor;
                    cover.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
                    cover.userInteractionEnabled = NO;
                    cover.accessibilityElementsHidden = YES;
                    UIImageView *mark = [[UIImageView alloc] initWithImage:[UIImage imageNamed:@"LaunchStar"]];
                    mark.tintColor = [UIColor colorNamed:@"LaunchStarColor"];
                    mark.contentMode = UIViewContentModeScaleAspectFit;
                    mark.translatesAutoresizingMaskIntoConstraints = NO;
                    [cover addSubview:mark];
                    [NSLayoutConstraint activateConstraints:@[
                        [mark.centerXAnchor constraintEqualToAnchor:cover.centerXAnchor],
                        [mark.centerYAnchor constraintEqualToAnchor:cover.centerYAnchor],
                        [mark.widthAnchor constraintEqualToConstant:288],
                        [mark.heightAnchor constraintEqualToConstant:288]
                    ]];
                    [window addSubview:cover];
                    [cover layoutIfNeeded];
                    [covers addObject:cover];
                }
            }
            if (covers.count) elo_record_cover_timing(EloCoverTimingAdded);
        };
        void (^removeCovers)(void) = ^{
            BOOL hadCover = covers.count > 0;
            for (UIView *cover in covers) [cover removeFromSuperview];
            [covers removeAllObjects];
            if (hadCover) elo_record_cover_timing(EloCoverTimingRemoved);
        };
        BOOL (^isForegroundInactive)(void) = ^BOOL {
            if (UIApplication.sharedApplication.applicationState != UIApplicationStateInactive) return NO;
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                if (![scene isKindOfClass:UIWindowScene.class]
                    || scene.activationState != UISceneActivationStateForegroundInactive) continue;
                for (UIWindow *window in ((UIWindowScene *)scene).windows) {
                    if (window.isKeyWindow) return YES;
                }
            }
            return NO;
        };
        [center addObserverForName:@"elo.privacy.unlockPrompt.begin" object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                unlockState.begin(UIApplication.sharedApplication.applicationState == UIApplicationStateActive, covers.count > 0);
                if (!unlockState.prompt) return;
                elo_record_cover_timing(EloCoverTimingPromptBegin);
            }];
        [center addObserverForName:@"elo.privacy.unlockPrompt.end" object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                BOOL needsCover = unlockState.endNeedsCover(isForegroundInactive());
                elo_record_cover_timing(EloCoverTimingPromptEnd);
                // Keep the locked login screen visible until native profile
                // verification completes, without flashing the privacy cover.
                if (needsCover && UIApplication.sharedApplication.applicationState != UIApplicationStateActive) addCover();
            }];
        [center addObserverForName:@"elo.privacy.unlockPrompt.reset" object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                unlockState.reset();
                if (UIApplication.sharedApplication.applicationState != UIApplicationStateActive) addCover();
            }];
        [center addObserverForName:@"elo.privacy.unlockPrompt.complete" object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                // Only Rust can send this after verifying the biometric key and
                // opening the profile. UIKit can stay inactive after Face ID has
                // returned. Reveal that authenticated foreground view now;
                // background snapshots still always receive a fresh cover.
                if (unlockState.complete(isForegroundInactive())) {
                    removeCovers();
                    elo_record_cover_timing(EloCoverTimingUnlockRevealed);
                } else if (UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
                    addCover();
                }
            }];
        [center addObserverForName:@"elo.privacy.unlockFrame" object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                elo_record_cover_timing(EloCoverTimingUnlockFrame);
            }];
        [center addObserverForName:UIApplicationWillResignActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                elo_record_cover_timing(EloCoverTimingResignActive);
                if (!unlockState.resignNeedsCover()) {
                    elo_record_cover_timing(EloCoverTimingSkipped);
                    return;
                }
                addCover();
            }];
        [center addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                // Background snapshots must remain private, even if the user
                // leaves the app or locks the phone during the Face ID prompt.
                unlockState.reset();
                elo_record_cover_timing(EloCoverTimingBackground);
                addCover();
            }];
        [center addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                unlockState.reset();
                elo_record_cover_timing(EloCoverTimingBecomeActive);
                removeCovers();
            }];
    });
}
