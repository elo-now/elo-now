#import "Privacy.h"
#import <UIKit/UIKit.h>

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
        [center addObserverForName:UIApplicationWillResignActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                if (covers.count) return;
                for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                    if (![scene isKindOfClass:UIWindowScene.class]) continue;
                    for (UIWindow *window in ((UIWindowScene *)scene).windows) {
                        if (!window.isKeyWindow) continue;
                        UIView *cover = [[UIView alloc] initWithFrame:window.bounds];
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
            }];
        [center addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                for (UIView *cover in covers) [cover removeFromSuperview];
                [covers removeAllObjects];
            }];
    });
}
