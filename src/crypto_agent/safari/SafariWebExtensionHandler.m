#import <Foundation/Foundation.h>
#import <SafariServices/SafariServices.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <string.h>

@interface SafariWebExtensionHandler : NSObject <NSExtensionRequestHandling>
- (NSDictionary *)processRequest:(NSData *)request;
@end

@implementation SafariWebExtensionHandler

- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context {
    NSExtensionItem *item = context.inputItems.firstObject;
    id message = [item isKindOfClass:NSExtensionItem.class] ? item.userInfo[SFExtensionMessageKey] : nil;
    NSDictionary *response = @{@"ok": @NO, @"code": @"invalid_request"};
    if ([message isKindOfClass:NSDictionary.class] && [NSJSONSerialization isValidJSONObject:message]) {
        NSData *request = [NSJSONSerialization dataWithJSONObject:message options:0 error:NULL];
        if (request.length > 0 && request.length <= 16384) {
            response = [self processRequest:request];
        }
    }
    NSExtensionItem *reply = [[NSExtensionItem alloc] init];
    reply.userInfo = @{SFExtensionMessageKey: response};
    [context completeRequestReturningItems:@[reply] completionHandler:nil];
}

- (NSDictionary *)processRequest:(NSData *)request {
    NSBundle *bundle = [NSBundle bundleForClass:self.class];
    NSURL *frameworks = bundle.privateFrameworksURL;
    NSURL *config = [bundle URLForResource:@"crypto-agent" withExtension:@"json"];
    NSURL *appContents = bundle.bundleURL.URLByDeletingLastPathComponent.URLByDeletingLastPathComponent;
    NSURL *library = [appContents URLByAppendingPathComponent:@"Frameworks/libhybrid-pq-cp-abe.dylib"];
    typedef char *(*HandleRequest)(const void *, size_t, const char *, const char *);
    typedef void (*FreeResponse)(char *);
    static HandleRequest handle;
    static FreeResponse release;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURL *bridge = [frameworks URLByAppendingPathComponent:@"libcpqa_crypto_agent.dylib"];
        if (bridge) {
            // Keep the bridge and its native runtime loaded for the extension's lifetime.
            void *loaded = dlopen(bridge.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
            if (loaded) {
                handle = (HandleRequest)dlsym(loaded, "cpqa_safari_handle_request");
                release = (FreeResponse)dlsym(loaded, "cpqa_safari_free_response");
            }
        }
    });
    if (!handle || !release || !config || !library) {
        return @{@"ok": @NO, @"code": @"invalid_installation"};
    }
    char *result = handle(request.bytes, request.length, config.fileSystemRepresentation,
                          library.fileSystemRepresentation);
    if (!result) {
        return @{@"ok": @NO, @"code": @"host_unreachable"};
    }
    NSData *data = [NSData dataWithBytes:result length:strlen(result)];
    release(result);
    id reply = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [reply isKindOfClass:NSDictionary.class] ? reply : @{@"ok": @NO, @"code": @"host_unreachable"};
}

@end
