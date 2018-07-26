//
//  RNTrustKitPlugin.m
//  RNTrustKitPlugin
//
//  Created by Bjarte Bore on 22.05.2017.
//
//

#import "RNTrustKitPlugin.h"
#import "TrustKit/TrustKit.h"

//#import <React/RCTConvert.h>



static BOOL _isTrustKitInitialized = NO;
static NSString *ErrorDomain = @"RNTrustKitPluginErrorDomain";
@implementation RNTrustKitPlugin

RCT_EXPORT_MODULE();

RCT_REMAP_METHOD(configure,
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
    if (_isTrustKitInitialized) {
        reject(
               @"trustkit_initialized",
               @"Trustkit is allready initialized",
               [NSError errorWithDomain: ErrorDomain
                                   code: -2
                               userInfo: nil]);
    }
    @try {

        [TrustKit initialize];
        _isTrustKitInitialized = YES;
        resolve( @"success" );
    }
    @catch (NSException *exception)
    {
        reject( @"trustkit_config_failed", @"Not able to configure TrustKit",
               [NSError errorWithDomain: ErrorDomain
                                   code: -2
                               userInfo: nil]);
    }
};

RCT_REMAP_METHOD(configure,
                 config:(NSDictionary *)config
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
    if (_isTrustKitInitialized) {
        reject(
               @"trustkit_initialized",
               @"Trustkit is allready initialized",
               [NSError errorWithDomain: ErrorDomain
                                   code: -2
                               userInfo: nil]);
        return;
    }

    @try
    {

        NSMutableDictionary *trustKitConfig = [NSMutableDictionary dictionary];

        BOOL swizzleNetworkDelegates = [[config objectForKey:@"SwizzleNetworkDelegates" ] boolValue];
        [trustKitConfig
         setObject: @(swizzleNetworkDelegates)
         forKey:kTSKSwizzleNetworkDelegates];

        NSMutableDictionary *nextPinnedDomains= [NSMutableDictionary dictionary];

        if ([[config valueForKey:@"PinnedDomain"] isKindOfClass:[NSDictionary class]]){
            NSDictionary *tskPinnedDomains = [config objectForKey:@"PinnedDomain"];
            NSArray *keys = [tskPinnedDomains allKeys];

            for (NSString *key in keys) {

                // incoming domain config
                NSDictionary *domainConfig = [tskPinnedDomains valueForKey:key];

                // outgoing domain config
                NSMutableDictionary *nextDomainConfig = [NSMutableDictionary dictionary];



                if ([[domainConfig valueForKey:@"PublicKeyAlgorithms"] isKindOfClass:[NSArray class]]) {
                    NSMutableArray *nextPublicKeyAlgorithms = [NSMutableArray array];

                    for (NSString *algorithm in [domainConfig valueForKey:@"PublicKeyAlgorithms"]) {

                        if ([algorithm isEqual:@"AlgorithmRsa2048"]) {
                            [nextPublicKeyAlgorithms addObject:kTSKAlgorithmRsa2048];
                        }
                        else if ([algorithm isEqual:@"AlgorithmRsa4096"]) {
                            [nextPublicKeyAlgorithms addObject:kTSKAlgorithmRsa4096];
                        }
                    }
                    [nextDomainConfig
                     setObject:nextPublicKeyAlgorithms
                     forKey:kTSKPublicKeyAlgorithms];
                }

                if ([[domainConfig valueForKey:@"PublicKeyHashes"] isKindOfClass:[NSArray class]]) {
                    [nextDomainConfig
                     setObject: [domainConfig valueForKey:@"PublicKeyHashes"]
                     forKey:kTSKPublicKeyHashes];
                }

                BOOL includeSubdomains = [[domainConfig objectForKey:@"IncludeSubdomains" ] boolValue];

                [nextDomainConfig
                 setObject: @(includeSubdomains)
                 forKey:kTSKIncludeSubdomains];

                BOOL enforcePinning = [[domainConfig objectForKey:@"EnforcePinning" ] boolValue];
                [nextDomainConfig
                 setObject: @(enforcePinning)
                 forKey:kTSKEnforcePinning];

                if ([[domainConfig valueForKey:@"ReportUris"] isKindOfClass:[NSArray class]]) {
                    [nextDomainConfig
                     setObject: [domainConfig valueForKey:@"ReportUris"]
                     forKey:kTSKReportUris];
                }

                // Append the next domain config to our configuration
                [nextPinnedDomains
                 setObject:nextDomainConfig
                 forKey:key];

            }

        }

        [trustKitConfig
         setObject:nextPinnedDomains
         forKey:kTSKPinnedDomains];

//        [TrustKit initializeWithConfiguration:trustKitConfig];
        [TrustKit initSharedInstanceWithConfiguration:trustKitConfig]; // for TrustKit v> 1.42


        _isTrustKitInitialized = YES;

        resolve(@"success");

        //[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch (NSException *e)
    {
        reject( @"trustkit_config_failed", @"Not able to configure TrustKit",
               [NSError errorWithDomain: ErrorDomain
                                   code: -2
                               userInfo: nil]);
    }
    //  }];
}


@end
