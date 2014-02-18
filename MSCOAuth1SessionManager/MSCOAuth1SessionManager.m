//
//  SRBOAuth1SessionManager.m
//  SRBNetworkStack
//
//  Created by Manfred Scheiner (@scheinem) on 25.01.14.
//  Copyright (c) 2014 Manfred Scheiner (@scheinem). All rights reserved.
//

#import "MSCOAuth1SessionManager.h"
#import <CommonCrypto/CommonHMAC.h>

NSString *const MSCOAuth1CallbackKey            = @"oauth_callback";
NSString *const MSCOAuth1ConsumerKeyKey         = @"oauth_consumer_key";
NSString *const MSCOAuth1NonceKey               = @"oauth_nonce";
NSString *const MSCOAuth1SignatureKey           = @"oauth_signature";
NSString *const MSCOAuth1SignatureMethodKey     = @"oauth_signature_method";
NSString *const MSCOAuth1TimestampKey           = @"oauth_timestamp";
NSString *const MSCOAuth1TokenKey               = @"oauth_token";
NSString *const MSCOAuth1TokenSecretKey         = @"oauth_token_secret";
NSString *const MSCOAuth1VerifierKey            = @"oauth_verifier";
NSString *const MSCOAuth1VersionKey             = @"oauth_version";

@interface MSCOAuth1SessionManager ()

@property (nonatomic, strong, readwrite) NSURL *callbackURL;

@property (nonatomic, strong) NSString *applicationKey;
@property (nonatomic, strong) NSString *applicationSecret;

@property (nonatomic, strong) NSString *accessToken;
@property (nonatomic, strong) NSString *accessTokenSecret;

@property (nonatomic, strong) NSString *requestToken;
@property (nonatomic, strong) NSString *requestTokenSecret;

@property (nonatomic, strong) NSString *verifier;

@property (nonatomic, assign) dispatch_once_t createMSCOAuth1ResponseSerializerOnceToken;
@property (nonatomic, strong) AFHTTPResponseSerializer *mscOAuth1ResponseSerializer;

@end

@implementation MSCOAuth1SessionManager

////////////////////////////////////////////////////////////////////////
#pragma mark - Life Cycle
////////////////////////////////////////////////////////////////////////

- (instancetype)initWithBaseURL:(NSURL *)baseURL applicationKey:(NSString *)applicationKey applicationSecret:(NSString *)applicationSecret callbackURL:(NSURL *)callbackURL {
    self = [super initWithBaseURL:baseURL];
    if (self) {
        _applicationKey = applicationKey;
        _applicationSecret = applicationSecret;
        _callbackURL = callbackURL;
        
        _signatureMethod = MSCOAuth1SignatureMethodHMACSHA1;
        
        _mscOAuth1ResponseSerializer = [AFHTTPResponseSerializer serializer];
    }
    return self;
}

- (void)fetchRequestTokenUsingResource:(NSString *)resource withCompletionBlock:(mscOAuth1SessionManager_fetchTokenCompletionBlock)completionBlock {
    
    // Remove old registration so that upcoming methods check that we want a new registration.
    self.accessToken = nil;
    self.accessTokenSecret = nil;
    
    NSDictionary *queryParameters = @{MSCOAuth1CallbackKey : self.callbackURL.absoluteString};
    NSString *url = [self signedURLWithQueryParameters:queryParameters httpMethod:@"POST" signatureMethod:self.signatureMethod resource:resource];
    
    [super POST:url parameters:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:NSASCIIStringEncoding];
        NSMutableDictionary *responseParameters = [self parametersDictionaryWithQueryString:responseString];
        
        // Filter request token and request token secret out to avoid that these information is contained in the callback dictionary.
        self.requestToken = [responseParameters objectForKey:MSCOAuth1TokenKey];
        [responseParameters removeObjectForKey:MSCOAuth1TokenKey];
        self.requestTokenSecret = [responseParameters objectForKey:MSCOAuth1TokenSecretKey];
        [responseParameters removeObjectForKey:MSCOAuth1TokenSecretKey];
        
        if (completionBlock) {
            completionBlock(responseParameters, nil);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSLog(@"error requestToken: %@", error);
        completionBlock(nil, error);
    }];
}

- (NSURLRequest *)authorizationRequestUsingResource:(NSString *)resource {
    if (self.requestToken.length > 0) {
        NSString *url = [NSString stringWithFormat:@"%@?oauth_token=%@&oauth_callback=%@", [self urlForResource:resource], self.requestToken,[self fullyPercentEscapedString:self.callbackURL.absoluteString]];
        return [NSURLRequest requestWithURL:[NSURL URLWithString:url]];
    }
    return nil;
}

- (BOOL)handleOpenURL:(NSURL *)url {
    if ([url.scheme isEqualToString:self.callbackURL.scheme] &&
        [url.host isEqualToString:self.callbackURL.host] &&
        [url.path isEqualToString:self.callbackURL.path]) {
        
        NSDictionary *parameters = [self parametersDictionaryWithQueryString:url.query];
        if ([[parameters objectForKey:@"oauth_token"] isEqualToString:self.requestToken]) {
            self.verifier = [parameters objectForKey:@"oauth_verifier"];
            if (self.verifier.length > 0) {
                return YES;
            }
        }
        return NO;
    }
    return NO;
}

- (void)fetchAccessTokenUsingResource:(NSString *)resource withCompletionBlock:(mscOAuth1SessionManager_fetchTokenCompletionBlock)completionBlock {
    
    NSDictionary *queryParameters = @{MSCOAuth1TokenKey : self.requestToken,
                                      MSCOAuth1VerifierKey : self.verifier};
    NSString *url = [self signedURLWithQueryParameters:queryParameters httpMethod:@"POST" signatureMethod:self.signatureMethod resource:resource];
    [super POST:url parameters:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        NSString *responseString = [[NSString alloc] initWithData:responseObject encoding:NSASCIIStringEncoding];
        NSMutableDictionary *responseParameters = [self parametersDictionaryWithQueryString:responseString];
        
        // Filter request token and request token secret out to avoid that these information is contained in the callback dictionary.
        self.accessToken = [responseParameters objectForKey:MSCOAuth1TokenKey];
        [responseParameters removeObjectForKey:MSCOAuth1TokenKey];
        self.accessTokenSecret = [responseParameters objectForKey:MSCOAuth1TokenSecretKey];
        [responseParameters removeObjectForKey:MSCOAuth1TokenSecretKey];
        
        // Clean up registration process
        self.requestToken = nil;
        self.requestTokenSecret = nil;
        self.verifier = nil;
        
        if (completionBlock) {
            completionBlock(responseParameters, nil);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSLog(@"error accessToken: %@", error);
        completionBlock(nil, error);
    }];
}

////////////////////////////////////////////////////////////////////////
#pragma mark - AFHTTPSessionManager
////////////////////////////////////////////////////////////////////////

- (NSURLSessionDataTask *)DELETE:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {
    [self setAuthorizationHeaderForQueryParameters:nil httpMethod:@"DELETE" signatureMethod:self.signatureMethod resource:URLString];
    return [super DELETE:URLString parameters:parameters success:success failure:failure];
}

- (NSURLSessionDataTask *)HEAD:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {
    [self setAuthorizationHeaderForQueryParameters:nil httpMethod:@"HEAD" signatureMethod:self.signatureMethod resource:URLString];
    return [super HEAD:URLString parameters:parameters success:success failure:failure];
}

- (NSURLSessionDataTask *)GET:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {
    
    NSDictionary *queryParameters = nil;
    NSString *urlWithoutQuery = URLString;
    if ([URLString rangeOfString:@"?"].location != NSNotFound) {
        NSString *queryString = [URLString substringFromIndex:[URLString rangeOfString:@"?"].location + 1];
        queryParameters = [self parametersDictionaryWithQueryString:queryString];
        
        urlWithoutQuery = [URLString substringToIndex:[URLString rangeOfString:@"?"].location];
    }
    
    [self setAuthorizationHeaderForQueryParameters:queryParameters httpMethod:@"GET" signatureMethod:self.signatureMethod resource:urlWithoutQuery];
    return [super GET:URLString parameters:parameters success:success failure:failure];
}

- (NSURLSessionDataTask *)PATCH:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {
    [self setAuthorizationHeaderForQueryParameters:nil httpMethod:@"PATCH" signatureMethod:self.signatureMethod resource:URLString];
    return [super PATCH:URLString parameters:parameters success:success failure:failure];
}

- (NSURLSessionDataTask *)POST:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {
    [self setAuthorizationHeaderForQueryParameters:nil httpMethod:@"POST" signatureMethod:self.signatureMethod resource:URLString];
    return [super POST:URLString parameters:parameters success:success failure:failure];
}

- (NSURLSessionDataTask *)PUT:(NSString *)URLString parameters:(NSDictionary *)parameters success:(void (^)(NSURLSessionDataTask *, id))success failure:(void (^)(NSURLSessionDataTask *, NSError *))failure {
    [self setAuthorizationHeaderForQueryParameters:nil httpMethod:@"PUT" signatureMethod:self.signatureMethod resource:URLString];
    return [super PUT:URLString parameters:parameters success:success failure:failure];
}

- (void)setResponseSerializer:(AFHTTPResponseSerializer<AFURLResponseSerialization> *)responseSerializer {
    dispatch_once(&_createMSCOAuth1ResponseSerializerOnceToken, ^{
        self.mscOAuth1ResponseSerializer = [AFHTTPResponseSerializer serializer];
    });
    super.responseSerializer = [AFCompoundResponseSerializer compoundSerializerWithResponseSerializers:@[responseSerializer, self.mscOAuth1ResponseSerializer]];
}

////////////////////////////////////////////////////////////////////////
#pragma mark - PRIVATE
#pragma mark - url generators
////////////////////////////////////////////////////////////////////////

// ONLY use this for the requestToken and accessToken fetch! For all other calls use the authorization header.
- (NSString *)signedURLWithQueryParameters:(NSDictionary *)queryParameters httpMethod:(NSString *)httpMethod signatureMethod:(MSCOAuth1SignatureMethod)signatureMethod resource:(NSString *)resource {
    
    NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithDictionary:queryParameters];
    [parameters addEntriesFromDictionary:[self authorizationParametersDictionaryForSignatureMethod:signatureMethod]];
    
    NSString *queryString = [self queryStringWithParametersDictionary:parameters];
    NSString *signature = [self signatureUsingMethod:signatureMethod httpMethod:httpMethod resource:resource queryString:queryString];
    
    // generate authorization string
    NSMutableString *authorizationString = [NSMutableString stringWithString:@"OAuth "];
    [parameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if ([key hasPrefix:@"oauth_"]) {
            [authorizationString appendFormat:@"%@=\"%@\", ", key, obj];
        }
    }];
    [authorizationString appendFormat:@"%@=\"%@\"", MSCOAuth1SignatureKey, signature];
    if (self.accessToken) {
        [self.requestSerializer setValue:authorizationString forHTTPHeaderField:@"Authorization"];
    }
    
    return [NSString stringWithFormat:@"%@?%@&%@=%@", resource, queryString, MSCOAuth1SignatureKey, signature];
}

- (NSString *)urlForResource:(NSString *)resource {
    NSString *url = nil;
    if ([resource hasPrefix:@"/"]) {
        resource = [resource substringFromIndex:1];
    }
    if ([self.baseURL.absoluteString hasSuffix:@"/"]) {
        url = [self.baseURL.absoluteString stringByAppendingString:resource];
    } else {
        url = [NSString stringWithFormat:@"%@/%@", self.baseURL.absoluteString, resource];
    }
    return url;
}

////////////////////////////////////////////////////////////////////////
#pragma mark - OAuth 1 authorization helpers
////////////////////////////////////////////////////////////////////////

- (void)setAuthorizationHeaderForQueryParameters:(NSDictionary *)queryParameters httpMethod:(NSString *)httpMethod signatureMethod:(MSCOAuth1SignatureMethod)signatureMethod resource:(NSString *)resource {
    // Collect all parameters that will be passed to the server during this call
    NSMutableDictionary *parameters = [NSMutableDictionary dictionaryWithDictionary:queryParameters];
    [parameters addEntriesFromDictionary:[self authorizationParametersDictionaryForSignatureMethod:signatureMethod]];
    
    NSString *queryString = [self queryStringWithParametersDictionary:parameters];
    NSString *signature = [self signatureUsingMethod:signatureMethod httpMethod:httpMethod resource:resource queryString:queryString];
    
    // generate authorization string
    NSMutableString *authorizationString = [NSMutableString stringWithString:@"OAuth "];
    [parameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if ([key hasPrefix:@"oauth_"]) {
            [authorizationString appendFormat:@"%@=\"%@\", ", key, obj];
        }
    }];
    [authorizationString appendFormat:@"%@=\"%@\"", MSCOAuth1SignatureKey, signature];
    [self.requestSerializer setValue:authorizationString forHTTPHeaderField:@"Authorization"];
}

- (NSMutableDictionary *)authorizationParametersDictionaryForSignatureMethod:(MSCOAuth1SignatureMethod)signatureMethod {
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    [parameters setObject:self.applicationKey forKey:MSCOAuth1ConsumerKeyKey];
    [parameters setObject:@"1.0" forKey:MSCOAuth1VersionKey];
    
    NSString *token = self.accessToken;
    if (self.requestToken.length > 0) {
        token = self.requestToken;
    }
    if (token) {
        [parameters setObject:token forKey:MSCOAuth1TokenKey];
    }
    
    if (self.signatureMethod == MSCOAuth1SignatureMethodPlaintext) {
        [parameters setObject:@"PLAINTEXT" forKey:MSCOAuth1SignatureMethodKey];
    } else {
        [parameters setObject:@"HMAC-SHA1" forKey:MSCOAuth1SignatureMethodKey];
        [parameters setObject:[self nonce] forKey:MSCOAuth1NonceKey];
        [parameters setObject:[self currentTimestamp] forKey:MSCOAuth1TimestampKey];
    }
    return parameters;
}

////////////////////////////////////////////////////////////////////////
#pragma mark - OAuth 1 signature helpers
////////////////////////////////////////////////////////////////////////

- (NSString *)signatureUsingMethod:(MSCOAuth1SignatureMethod)method httpMethod:(NSString *)httpMethod resource:(NSString *)resource queryString:(NSString *)queryString {
    NSString *key = [self key];
    
    if (method == MSCOAuth1SignatureMethodPlaintext) {
        return [self fullyPercentEscapedString:key];
    } else if (method == MSCOAuth1SignatureMethodHMACSHA1){
        NSString *data = [NSString stringWithFormat:@"%@&%@&%@", [httpMethod uppercaseString], [self fullyPercentEscapedString:[self urlForResource:resource]], [self fullyPercentEscapedString:queryString]];
        NSString *signature = [self hmacSHA1WithKey:[key dataUsingEncoding:NSASCIIStringEncoding] data:[data dataUsingEncoding:NSASCIIStringEncoding]];
        return [self fullyPercentEscapedString:signature];
    }
    return nil;
}

- (NSString *)plaintextMethodSignatureForAccessTokenRequest:(BOOL)accessTokenRequest {
    return [self signatureUsingMethod:MSCOAuth1SignatureMethodPlaintext httpMethod:nil resource:nil queryString:nil];
}

- (NSString *)key {
    /**
     * If we have an requestToken stored, this means that we are in a registration process currently and
     * we have to use this one as part of the key.
     */
    NSString *tokenSecret = self.accessTokenSecret;
    if (self.requestTokenSecret.length > 0) {
        tokenSecret = self.requestTokenSecret;
    }
    
    if (tokenSecret.length > 0) {
        return [NSString stringWithFormat:@"%@&%@", self.applicationSecret, tokenSecret];
    }
    return [NSString stringWithFormat:@"%@&", self.applicationSecret];
}

- (NSString *)hmacSHA1WithKey:(NSData *)key data:(NSData *)data {
    NSMutableData *hmac = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, key.bytes, key.length, data.bytes, data.length, hmac.mutableBytes);
    return [hmac base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

////////////////////////////////////////////////////////////////////////
#pragma mark - query string helpers
////////////////////////////////////////////////////////////////////////

- (NSMutableDictionary *)parametersDictionaryWithQueryString:(NSString *)queryString {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    [[queryString componentsSeparatedByString:@"&"] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        NSUInteger splitLocation = [(NSString *)obj rangeOfString:@"="].location;
        
        NSString *object = [(NSString *)obj substringFromIndex:(splitLocation + 1)];
        if ([object isEqualToString:@"true"]) {
            [dictionary setObject:[NSNumber numberWithBool:YES] forKey:[(NSString *)obj substringToIndex:splitLocation]];
        } else if ([object isEqualToString:@"false"]) {
            [dictionary setObject:[NSNumber numberWithBool:NO] forKey:[(NSString *)obj substringToIndex:splitLocation]];
        } else {
            [dictionary setObject:object forKey:[(NSString *)obj substringToIndex:splitLocation]];
        }
    }];
    return dictionary;
}

- (NSString *)queryStringWithParametersDictionary:(NSDictionary *)queryParameters {
    // Sort parameters alphabetically (needed for valid signature) and combine them into a queryString.
    NSMutableString *queryString = [NSMutableString string];
    [[[queryParameters allKeys] sortedArrayUsingComparator:^NSComparisonResult(id obj1, id obj2) {
        return [(NSString *)obj1 compare:(NSString *)obj2 options:NSCaseInsensitiveSearch];
    }] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        if (queryString.length > 0) {
            [queryString appendString:@"&"];
        }
        [queryString appendFormat:@"%@=%@", obj, [self fullyPercentEscapedString:(NSString *)[queryParameters objectForKey:obj]]];
    }];
    return queryString;
}

////////////////////////////////////////////////////////////////////////
#pragma mark - other stuff
////////////////////////////////////////////////////////////////////////

- (NSString *)fullyPercentEscapedString:(NSString *)string {
    string = [string stringByAddingPercentEscapesUsingEncoding:NSASCIIStringEncoding];
    string = [string stringByReplacingOccurrencesOfString:@"&" withString:@"%26"];
    string = [string stringByReplacingOccurrencesOfString:@"'" withString:@"%27"];
    string = [string stringByReplacingOccurrencesOfString:@"(" withString:@"%28"];
    string = [string stringByReplacingOccurrencesOfString:@")" withString:@"%29"];
    string = [string stringByReplacingOccurrencesOfString:@"*" withString:@"%2A"];
    string = [string stringByReplacingOccurrencesOfString:@"+" withString:@"%2B"];
    string = [string stringByReplacingOccurrencesOfString:@"," withString:@"%2C"];
    string = [string stringByReplacingOccurrencesOfString:@"/" withString:@"%2F"];
    string = [string stringByReplacingOccurrencesOfString:@":" withString:@"%3A"];
    string = [string stringByReplacingOccurrencesOfString:@":" withString:@"%3B"];
    string = [string stringByReplacingOccurrencesOfString:@"=" withString:@"%3D"];
    string = [string stringByReplacingOccurrencesOfString:@"?" withString:@"%3F"];
    string = [string stringByReplacingOccurrencesOfString:@"@" withString:@"%40"];
    return string;
}

- (NSString *)currentTimestamp {
    return [NSString stringWithFormat:@"%d", (int)[[NSDate date] timeIntervalSince1970]];
}

- (NSString *)nonce {
    return [[[NSUUID UUID] UUIDString] stringByReplacingOccurrencesOfString:@"-" withString:@""];
}

@end
