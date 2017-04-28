@import Foundation;
@import Security;

#import "TCertChecker.h"

static NSString* NSStringFromSecTrustResult(SecTrustResultType result);

@interface NSData (NSDataAdditions)

+ (NSData *) base64DataFromString:(NSString *)string;

@end

const NSErrorDomain errorDomain = @"org.vovkasm.TCertChecker";

@implementation TCertChecker

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(validateCertificate:(NSString*)pemData resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    NSString* startMarker = @"-----BEGIN CERTIFICATE-----";
    NSString* endMarker = @"-----END CERTIFICATE-----";

    NSScanner* scanner = [NSScanner scannerWithString:pemData];
    [scanner scanUpToString:startMarker intoString:nil];
    [scanner scanString:startMarker intoString:nil];
    NSString* pemOnly = nil;
    [scanner scanUpToString:endMarker intoString:&pemOnly];

    NSData* certData = [NSData base64DataFromString:pemOnly];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        BOOL result = NO;
        NSDictionary* resultDict = nil;
        NSError* error = nil;

        SecCertificateRef cert = nil;
        CFArrayRef certs = nil;
        SecTrustRef trust = nil;

        cert = SecCertificateCreateWithData(nil, (__bridge CFDataRef)certData);
        if (cert == nil) {
            error = [self errorWithCode:1 message:@"Incorrect format of the certificate, should be PEM"];
            goto finish;
        }


        SecCertificateRef certArray[1] = { cert };
        certs = CFArrayCreate(nil, (CFTypeRef*)certArray, 1, nil);

        SecPolicyRef policy = SecPolicyCreateSSL(true, nil);
        OSStatus status = SecTrustCreateWithCertificates(certs, policy, &trust);
        CFRelease(policy);

        if (status != noErr) {
            error = [self errorWithCode:2 message:@"Can't create certificate trust"];
            goto finish;
        }

        SecTrustResultType trustResult;
        status = SecTrustEvaluate(trust, &trustResult);

        if (status != noErr) {
            error = [self errorWithCode:3 message:@"Can't evaluate certificate trust"];
            goto finish;
        }

        switch (trustResult) {
            case kSecTrustResultUnspecified:
            case kSecTrustResultProceed:
                result = YES;
                break;
            default:
                result = NO;
        }

        resultDict = (NSDictionary*)CFBridgingRelease(SecTrustCopyResult(trust));

    finish:
        if (cert != nil) CFRelease(cert);
        if (certs != nil) CFRelease(certs);
        if (trust != nil) CFRelease(trust);

        if (error == nil) {
            resolve([self resolveResult:result platformResult:resultDict]);
        } else {
            reject(@"error", [error localizedDescription], error);
        }
    });
}

- (NSDictionary*)resolveResult:(BOOL)valid platformResult:(NSDictionary*)result {
    NSMutableDictionary* platformResult = [result mutableCopy];
    if (platformResult[@"TrustResultValue"]) {
        id val = platformResult[@"TrustResultValue"];
        if ([val respondsToSelector:@selector(intValue)]) {
            platformResult[@"TrustResultValue"] = NSStringFromSecTrustResult([val intValue]);
        }
    }
    return @{@"valid":@(valid), @"platformResult":platformResult};
}

- (NSError*)errorWithCode:(NSInteger)code message:(NSString*)message {
    return [NSError errorWithDomain:errorDomain code:code userInfo:@{NSLocalizedDescriptionKey: message}];
}

@end

@implementation NSData (NSDataAdditions)

+ (NSData *)base64DataFromString: (NSString *)string {
    unsigned long ixtext, lentext;
    unsigned char ch, inbuf[4], outbuf[3];
    short i, ixinbuf;
    Boolean flignore, flendtext = false;
    const unsigned char *tempcstring;
    NSMutableData *theData;

    if (string == nil) return [NSData data];

    ixtext = 0;
    tempcstring = (const unsigned char *)[string UTF8String];
    lentext = [string length];
    theData = [NSMutableData dataWithCapacity: lentext];
    ixinbuf = 0;

    while (true) {
        if (ixtext >= lentext)
            break;

        ch = tempcstring [ixtext++];

        flignore = false;

        if ((ch >= 'A') && (ch <= 'Z')) { ch = ch - 'A'; }
        else if ((ch >= 'a') && (ch <= 'z')) { ch = ch - 'a' + 26; }
        else if ((ch >= '0') && (ch <= '9')) { ch = ch - '0' + 52; }
        else if (ch == '+') { ch = 62; }
        else if (ch == '=') { flendtext = true; }
        else if (ch == '/') { ch = 63; }
        else { flignore = true; }

        if (!flignore) {
            short ctcharsinbuf = 3;
            Boolean flbreak = false;

            if (flendtext) {
                if (ixinbuf == 0)
                    break;

                if ((ixinbuf == 1) || (ixinbuf == 2)) {
                    ctcharsinbuf = 1;
                }
                else {
                    ctcharsinbuf = 2;
                }

                ixinbuf = 3;
                flbreak = true;
            }
            
            inbuf [ixinbuf++] = ch;
            
            if (ixinbuf == 4) {
                ixinbuf = 0;
                
                outbuf[0] = (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
                outbuf[1] = ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
                outbuf[2] = ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
                
                for (i = 0; i < ctcharsinbuf; i++) {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
            if (flbreak)
                break;
        }
    }
    
    return theData;
}

@end

static NSString* NSStringFromSecTrustResult(SecTrustResultType result) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    switch(result) {
        case kSecTrustResultInvalid: return @"invalid";
        case kSecTrustResultProceed: return @"proceed";
        case kSecTrustResultConfirm: return @"confirm";
        case kSecTrustResultDeny: return @"deny";
        case kSecTrustResultUnspecified: return @"unspecified";
        case kSecTrustResultRecoverableTrustFailure: return @"recoverableTrustFailure";
        case kSecTrustResultFatalTrustFailure: return @"fatalTrustFailure";
        case kSecTrustResultOtherError: return @"otherError";
        default: return [NSString stringWithFormat:@"unknown(%u)", result];
    }
#pragma clang diagnostic pop
}
