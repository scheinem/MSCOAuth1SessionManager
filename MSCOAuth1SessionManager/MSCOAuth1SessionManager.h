//
//  SRBOAuth1SessionManager.h
//  SRBNetworkStack
//
//  Created by Manfred Scheiner (@scheinem) on 25.01.14.
//  Copyright (c) 2014 Manfred Scheiner (@scheinem). All rights reserved.
//
typedef NS_ENUM(NSUInteger, MSCOAuth1SignatureMethod) {
    MSCOAuth1SignatureMethodHMACSHA1 = 1,
    MSCOAuth1SignatureMethodPlaintext = 2
};

typedef void (^mscOAuth1SessionManager_fetchTokenCompletionBlock)(NSDictionary *response, NSError *error);

@interface MSCOAuth1SessionManager : AFHTTPSessionManager

@property (nonatomic, assign) MSCOAuth1SignatureMethod signatureMethod;

@property (nonatomic, strong, readonly) NSURL *callbackURL;

- (instancetype)initWithBaseURL:(NSURL *)baseURL applicationKey:(NSString *)applicationKey applicationSecret:(NSString *)applicationSecret callbackURL:(NSURL *)callbackURL;

- (void)fetchRequestTokenUsingResource:(NSString *)resource withCompletionBlock:(mscOAuth1SessionManager_fetchTokenCompletionBlock)completionBlock;

- (NSURLRequest *)authorizationRequestUsingResource:(NSString *)resource;

- (BOOL)handleOpenURL:(NSURL *)url;

- (void)fetchAccessTokenUsingResource:(NSString *)resource withCompletionBlock:(mscOAuth1SessionManager_fetchTokenCompletionBlock)completionBlock;

@end
