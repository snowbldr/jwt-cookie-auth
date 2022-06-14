/**
 * Create a hmac sha512 hash of the given value and salt
 * @param {string} value The value to hash
 * @param {string} salt A salt to use to create the hmac
 * @return {string} A base64 hash of the value
 */
export function createSha512Hmac(value: string, salt: string): string;
/**
 * Set cookies on the response. The cookies should be serialized strings.
 * If there are existing values for set-cookie, they will not be overridden.
 *
 * @param {AuthResponse} res The response object to set the cookies on
 * @param {...string} cookies The serialized cookies to add to the set-cookie header
 */
export function setCookies(res: AuthResponse, ...cookies: string[]): void;
/**
 * Delete the user's cookies.
 *
 * @param {AuthResponse} res The response object to set the cookies on
 * @param {...string} cookieNames The names of the cookies to add to the set-cookie header
 */
export function deleteCookies(res: AuthResponse, ...cookieNames: string[]): void;
/**
 * Get the parsed cookies from the request
 * @param {AuthRequest} req The request object to get cookies from
 * @return {object} An object containing the cookies by name
 */
export function getCookies(req: AuthRequest): object;
export class User {
    /**
     * @param {{ username: string, roles: Array.<string>= }} opts
     */
    constructor({ username, roles }: {
        username: string;
        roles: Array<string>;
    });
    /**
     * The user's unique name
     * @type string
     */
    username: string;
    /**
     * Roles assigned to the user
     * @type Array.<string>=
     */
    roles: Array<string> | undefined;
}
/**
 * Minimal JWT user data
 */
export class JwtUser extends User {
    /**
     * @param {{ username: string, roles: Array.<string>=, sub: string}} opts
     */
    constructor({ username, roles, sub }: {
        username: string;
        roles: Array<string>;
        sub: string;
    });
    /**
     * The user's unique name, synonym for username
     * @type string
     */
    sub: string;
}
/**
 * Minimal data for a persisted user capable of logging in
 */
export class PersistedUser extends User {
    /**
     *
     * @param {{username: string, roles: Array.<string>, passwordHash: string, salt: string, failedLogins: number=, lockedAt: Date=}} opts
     */
    constructor({ username, roles, passwordHash, salt, failedLogins, lockedAt }: {
        username: string;
        roles: Array<string>;
        passwordHash: string;
        salt: string;
        failedLogins: number;
        lockedAt: Date;
    });
    /**
     * A hash of the user's password and their salt
     * @type string
     */
    passwordHash: string;
    /**
     * A random unique string used to make the same password hash to a different value and prevent identifying shared passwords based on the hash
     * @type string
     */
    salt: string;
    /**
     * The number of failed login attempts so far
     * @type number=
     */
    failedLogins: number | undefined;
    /**
     * The point in time when this user became locked
     * @type Date=
     */
    lockedAt: Date | undefined;
}
export class UserLockEvent {
    /**
     *
     * @param {{username: string, action: string, failedLogins: number, lockedAt: Date=}} opts
     */
    constructor({ username, action, failedLogins, lockedAt }: {
        username: string;
        action: string;
        failedLogins: number;
        lockedAt: Date;
    });
    /**
     * The user's unique name
     * @type {string}
     */
    username: string;
    /**
     * The action that triggered the {@link AuthorizerOptions.setLockStatus} function, one of ('failedAttempt', 'locked', 'unlocked')
     * @type {string}
     */
    action: string;
    /**
     * The number of failed login attempts so far
     * @type {number}
     */
    failedLogins: number;
    /**
     * The point in time when this user became locked
     * @type {Date=}
     */
    lockedAt: Date | undefined;
}
export class LoginResult {
    /**
     *
     * @param {{jwtUser: JwtUser, authToken: string, authCookie: string, refreshToken: string=, refreshCookie: string=}} opts
     */
    constructor({ jwtUser, authToken, authCookie, refreshToken, refreshCookie }: {
        jwtUser: JwtUser;
        authToken: string;
        authCookie: string;
        refreshToken: string;
        refreshCookie: string;
    });
    /**
     * The user data that was encoded in the JWTs
     * @type JwtUser
     */
    jwtUser: JwtUser;
    /**
     * A JWT token to be used for authentication
     * @type string
     */
    authToken: string;
    /**
     * A cookie containing the authToken
     * @type string
     */
    authCookie: string;
    /**
     * A JWT token to be used for obtaining new auth tokens
     * only provided if refresh is enabled
     * @type string=
     */
    refreshToken: string | undefined;
    /**
     * A cookie containing the authToken
     * only provided if refresh is enabled
     * @type string=
     */
    refreshCookie: string | undefined;
}
/**
 * @typedef {object} AuthResponse Minimal required properties of a response object as used by JwtCookieAuthorizer
 * @property {(header: string) => string|Array.<string>} [getHeader] return the value of a header
 * @property {(header: string) => string|Array.<string>} [get] return the value of a header (available in frameworks like express)
 * @property {(header: string) => void} [setHeader] set the value of a header
 * @property {(header: string) => void} [set] set the value of a header (available in frameworks like express)
 * @property {number} statusCode Used to set the HTTP response status code
 * @property {string} statusMessage Used to set the HTTP response status message
 * @property {function} end End the current response
 */
/**
 * @typedef {object} AuthRequest Minimal required properties of a request object as used by JwtCookieAuthorizer
 * @property {object} [cookies] Parsed cookies received on the request, cookies are parsed from the header if not available
 * @property {object} headers Headers received on the request
 * @property {object} [user] The user object retrieved from the jwt
 *
 */
/**
 * Keys used to sign and verify JWTs
 * @typedef {object} JwtKeys
 * @property {!string|!Buffer=} private The private key passed to sign from https://www.npmjs.com/package/jsonwebtoken
 * If not passed, it will not be possible to generate new tokens.
 * @property {!string|!Buffer} public The public key passed to verify from https://www.npmjs.com/package/jsonwebtoken
 */
/**
 * Options for creating and verifying tokens
 * @typedef {object} TokenOptions
 * @property {string|Buffer=} secret The secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided
 * @property {JwtKeys=} keys Keys used to sign and verify JWTs, cannot be set if secret is provided
 * @property {object=} signOptions Options passed to sign when creating a token.
 *        Recommended to pass issuer and expiresIn at minimum.
 *        See https://www.npmjs.com/package/jsonwebtoken
 *        example: {issuer: 'my-app', expiresIn: '3m'}
 * @property {object=} verifyOptions Options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
 * @property {string=} cookieName The cookie name to store the token into, defaults to jwt-${name} where name is either auth or refresh
 * @property {object=} cookieConfig Configuration options to pass cookie.serialize See https://www.npmjs.com/package/cookie
 */
/**
 * Options for the tokens this verified deals with. Cookie names default to jwt-${tokenName}
 * @typedef {object} Tokens
 * @property {TokenOptions=} auth A token with a short expiration used for validating a user is authenticated. An expiresIn of 15m is used if not specified.
 *        expiresIn should be set to the maximum amount of time a session is allowed to remain idle.
 * @property {TokenOptions=} refresh A token with a long expiration used to refresh auth tokens. An expiresIn of 3d is used if not specified.
 *        expiresIn should be set to the maximum amount of time a user is allowed to be logged in for without re-authorizing.
 *        These tokens should be persisted, and removed when the user logs out, ending their session and preventing new tokens
 *        from being created. The {@link LoginOperations.storeRefreshToken} function is used to store the token when it's
 *        created, and the {@link LoginOperations.invalidateRefreshToken} function is used when the user is logged out to
 *        remove or mark the refresh token as invalid.
 */
/**
 * Functions related to logging in and out a user
 * @typedef LoginOperations
 * @property {loadUserByUsername} loadUserByUsername load the user data by username
 * @property {storeRefreshToken} storeRefreshToken Store a new refresh token
 * @property {checkRefreshTokenValid} checkRefreshTokenValid Check if a refresh token is valid
 * @property {invalidateRefreshToken} invalidateRefreshToken Invalidate the given refresh token
 * @property {hashPassword} hashPassword HMAC Hash the password and salt
 * @property {userToJwtPayload} userToJwtPayload Convert a {@link PersistedUser} to a {@link JwtUser}
 */
/**
 * A function to load the user data by username.
 * Implementation required if using any of {@link JwtCookieAuthorizer.basicAuthLogin} or {@link JwtCookieAuthorizer.basicAuthLoginMiddleware}
 * @typedef {(username: string, request: AuthRequest, response: AuthResponse) => Promise<PersistedUser>} loadUserByUsername
 * @param {string} username The name of the user to load
 * @param {AuthRequest} request The current request
 * @param {AuthResponse} response The current response
 * @return {Promise<PersistedUser>} The persisted user
 */
/**
 * Store a newly created refresh token. Not called if refresh is disabled.
 * This function should store the cookie in persistent storage (i.e. sql db, redis, etc).
 *
 * To save space, you can store a hash of the token instead of the whole token value.
 *
 * You must also implement invalidateRefreshToken, which removes the refresh token
 * from the persistent storage. This prevents the user from further refreshing their auth token and logs the user out
 * everywhere.
 *
 * @typedef {(jwtUser: JwtUser, token: string) => Promise<void>} storeRefreshToken
 * @param {JwtUser} jwtUser The decoded user payload from the jwt
 * @param {string} token The refresh token to store
 * @return {Promise<void>}
 */
/**
 * Check if the provided refresh token is valid to determine if it can be used to refresh an auth token.
 * Not called if refresh is disabled.
 *
 * If you would like to prevent calls to a datastore, have this function return true without any checks.
 *
 * Ideally, this should check in the data store whether this token is valid. This effectively makes this jwt authorizer
 * a stateful session, with the primary difference being that calls between refreshes don't need to hit a session store
 * to check if the session is valid. At a large scale, this will vastly reduce the amount of calls being made to a centralized
 * session store.
 *
 * The token is validated before this is called.
 *
 * @typedef {(jwtUser: JwtUser, token: string) => Promise<void>} checkRefreshTokenValid
 * @param {JwtUser} jwtUser The decoded user payload from the jwt
 * @param {string} token The refresh token to validate
 * @return {Promise<boolean>} Whether the token is valid or not
 */
/**
 * Remove a refresh token from persistent storage or otherwise mark it invalid. Not called if refresh is disabled.
 * @typedef {(jwtUser: JwtUser, token: string) => Promise<void>} invalidateRefreshToken
 * @param {JwtUser} jwtUser The decoded user payload from the jwt
 * @param {string} token The refresh token to store
 * @return {Promise<void>}
 */
/**
 * Hash the given password and salt. Uses sha512 hash from crypto package by default.
 *
 * @typedef {(password: string, salt: string) => Promise<string>} hashPassword
 * @param {string} password The password to hash
 * @param {string} salt A random unique string used to make the same password hash to a different value and prevent identifying shared passwords based on the hash
 * @return {Promise<string>}
 */
/**
 * Map a user to the jwt payload when a token is created.
 * @typedef {(user: PersistedUser) => Promise<JwtUser>} userToJwtPayload
 * @param {PersistedUser} user
 * @return Promise<JwtUser>
 */
/**
 * Options related to locking a user
 * @typedef {object} LockingOptions
 * @property {number=} maxFailedLogins Maximum number of login attempts to allow before locking the user. Defaults to 10.
 * @property {number=} lockSeconds Number of seconds to lock the user after reaching the max failed attempts. Defaults to 10 minutes.
 * @property {setLockStatus} setLockStatus Set the user's lock status
 */
/**
 * Update the user when it's lock status is changed.
 * This function should persist the changes to the user.
 * @typedef {(userLockEvent: UserLockEvent) => Promise<void>} setLockStatus
 * @param {UserLockEvent} userLockEvent The event that triggered the call to setLockStatus
 * @return {Promise<void>}
 */
/**
 *  Options passed to create a new JwtCookieAuthorizer
 *  TokenOptions properties are the defaults used if values are not passed for specific tokens, except for cookieName
 * @typedef {object} AuthorizerOptions
 * @property {LoginOperations} login Operations for login and refresh
 * @property {LockingOptions=} locking Options related to locking users, locking is disabled if this is not set
 * @property {Tokens=} tokens Token configurations
 * @property {boolean=} refreshEnabled Whether refresh tokens are enabled.
 *    This is true by default and the corresponding refresh methods must be provided on the LoginOperations.
 *
 *    If this is disabled, it will disable the ability to log out users, and will prevent refresh tokens from being created.
 *
 *    It is not recommended to disable refresh for anything important, but is fine for toy apps and non-critical applications
 * @property {string|Buffer=} secret The default secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided
 * @property {JwtKeys=} keys The default keys used to sign and verify JWTs, cannot be set if secret is provided
 * @property {object=} signOptions The default options passed to sign when creating a token.
 *        Recommended to pass issuer and expiresIn at minimum.
 *        See https://www.npmjs.com/package/jsonwebtoken
 *        example: {issuer: 'my-app', expiresIn: '3m'}
 * @property {object=} verifyOptions The default options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
 * @property {object=} cookieConfig The default configuration options to pass cookie.serialize See https://www.npmjs.com/package/cookie
 *
 */
/**
 * A middleware function
 * @typedef {(req: object, res: object, next: function(*=): void) => void} middleware
 * @param {object} req The current request
 * @param {object} res The outgoing response
 * @param {function(*=):void} next A function to trigger the next middleware
 * @return void
 */
/**
 * An object that handles creating and authenticating JWTs
 */
export class JwtCookieAuthorizer {
    /**
     * @param {AuthorizerOptions} authorizerOptions Options to configure the authorizer
     */
    constructor(authorizerOptions: AuthorizerOptions);
    /**
     * @return {middleware} A middleware that will authorize the request using the provided authorizer
     */
    basicAuthLoginMiddleware(): middleware;
    /**
     * Create a new middleware function that will exchange basic auth for a jwt token or will validate an existing jwt
     *
     * @return {middleware} A middleware that will authorize the request using this authorizer
     */
    authorizeMiddleware(): middleware;
    /**
     * Create a new middleware function that will exchange a valid jwt for a newer valid jwt
     * @param {boolean} reloadUser Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data
     * @return {middleware} A middleware to refresh jwt token cookies
     */
    refreshAuthMiddleware(reloadUser?: boolean): middleware;
    /**
     * Create a middleware that will log out the user when called
     * @return {middleware}
     */
    logoutMiddleware(): middleware;
    /**
     * Attempt to log the user in and create a new jwt token
     * @param {PersistedUser} user The user to log in
     * @param {string} password The plain text password to log the user in with
     * @return {LoginResult}
     * @throws {UnauthorizedError}
     */
    login(user: PersistedUser, password: string): LoginResult;
    /**
     * Verify the provided jwt cookie and set the user on the request to the parser user in the jwt
     * @param {AuthRequest} req The incoming request
     * @param {AuthResponse} res The outgoing response
     * @return {Promise<JwtUser>}
     * @throws {UnauthorizedError}
     */
    verifyAuth(req: AuthRequest, res: AuthResponse): Promise<JwtUser>;
    /**
     * Log the current user out by deleting their cookies and calling invalidateRefreshToken
     * @param {AuthRequest} req The current request
     * @param {AuthResponse} res The current response
     * @return {Promise<void>}
     */
    logout(req: AuthRequest, res: AuthResponse): Promise<void>;
    /**
     * Exchange a valid jwt token for a new one with a later expiration time
     * The request must contain a valid auth token and a valid refresh token (if refresh is enabled) to be accepted
     * You must refresh the auth cookie before either token expires to keep the session active
     * If either token is expired, the user must re-login
     * The new jwt is added as a cookie which overwrites the existing cookie
     * @param {AuthRequest} req The current request object
     * @param {AuthResponse} res The current response object
     * @param {boolean} reloadUser Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data
     * @return {Promise<void>}
     * @throws {UnauthorizedError}
     */
    refreshAuthCookie(req: AuthRequest, res: AuthResponse, reloadUser?: boolean): Promise<void>;
    /**
     * Log the user in using a basic auth header
     * @param {AuthRequest} req The current request with a headers object containing the request headers
     * @param {AuthResponse} res The current response to set the cookies on
     * @throws {UnauthorizedError}
     */
    basicAuthLogin(req: AuthRequest, res: AuthResponse): Promise<void>;
    /**
     * Get a cookie's value from the request
     * @param {AuthRequest} req The current request
     * @param {string} cookieName The cookie's value to get
     * @return {string}
     */
    getCookieValue(req: AuthRequest, cookieName: string): string;
    /**
     * @param {string} authHeader The authorization header value from the request
     * @return {{password: string, username: string}}
     * @throws {UnauthorizedError}
     */
    parseBasicAuthHeader(authHeader: string): {
        password: string;
        username: string;
    };
    #private;
}
export function hasAnyRole(userRoles: string[], ...requiredRoles: string[]): boolean;
export function hasAllRoles(userRoles: string[], ...requiredRoles: string[]): boolean;
export function hasAnyRoleMiddleware(...requiredRoles: string[]): middleware;
export function hasAllRolesMiddleware(...requiredRoles: string[]): middleware;
/**
 * An Error with an associated http statusCode and statusMessage
 * @property {number} statusCode Http status code associated with the exception
 * @property {string} statusMessage The status message to use on the response
 * @property {*=} [body] An object or message to use as the response body
 */
export class HttpStatusError extends Error {
    /**
     *
     * @param {number} statusCode
     * @param {string} statusMessage
     * @param {*=} body
     */
    constructor(statusCode: number, statusMessage: string, body?: any | undefined);
    statusCode: number;
    statusMessage: string;
    body: any;
}
/**
 * An HttpError with 401 statusCode and Unauthorized statusMessage
 * @property {*=} [body] An object or message to use as the response body
 * @property {Error=} [cause] The error that caused this error to be thrown, if any
 */
export class UnauthorizedError extends HttpStatusError {
    /**
     *
     * @param {*=} body
     * @param {Error=} cause
     */
    constructor(body?: any | undefined, cause?: Error | undefined);
}
/**
 * Minimal required properties of a response object as used by JwtCookieAuthorizer
 */
export type AuthResponse = {
    /**
     * return the value of a header
     */
    getHeader?: (header: string) => string | Array<string>;
    /**
     * return the value of a header (available in frameworks like express)
     */
    get?: (header: string) => string | Array<string>;
    /**
     * set the value of a header
     */
    setHeader?: (header: string) => void;
    /**
     * set the value of a header (available in frameworks like express)
     */
    set?: (header: string) => void;
    /**
     * Used to set the HTTP response status code
     */
    statusCode: number;
    /**
     * Used to set the HTTP response status message
     */
    statusMessage: string;
    /**
     * End the current response
     */
    end: Function;
};
/**
 * Minimal required properties of a request object as used by JwtCookieAuthorizer
 */
export type AuthRequest = {
    /**
     * Parsed cookies received on the request, cookies are parsed from the header if not available
     */
    cookies?: object;
    /**
     * Headers received on the request
     */
    headers: object;
    /**
     * The user object retrieved from the jwt
     */
    user?: object;
};
/**
 * Keys used to sign and verify JWTs
 */
export type JwtKeys = {
    /**
     * The private key passed to sign from https://www.npmjs.com/package/jsonwebtoken
     * If not passed, it will not be possible to generate new tokens.
     */
    private?: (string | Buffer) | undefined;
    /**
     * The public key passed to verify from https://www.npmjs.com/package/jsonwebtoken
     */
    public: string | Buffer;
};
/**
 * Options for creating and verifying tokens
 */
export type TokenOptions = {
    /**
     * The secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided
     */
    secret?: (string | Buffer) | undefined;
    /**
     * Keys used to sign and verify JWTs, cannot be set if secret is provided
     */
    keys?: JwtKeys | undefined;
    /**
     * Options passed to sign when creating a token.
     * Recommended to pass issuer and expiresIn at minimum.
     * See https://www.npmjs.com/package/jsonwebtoken
     * example: {issuer: 'my-app', expiresIn: '3m'}
     */
    signOptions?: object | undefined;
    /**
     * Options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
     */
    verifyOptions?: object | undefined;
    /**
     * The cookie name to store the token into, defaults to jwt-${name} where name is either auth or refresh
     */
    cookieName?: string | undefined;
    /**
     * Configuration options to pass cookie.serialize See https://www.npmjs.com/package/cookie
     */
    cookieConfig?: object | undefined;
};
/**
 * Options for the tokens this verified deals with. Cookie names default to jwt-${tokenName}
 */
export type Tokens = {
    /**
     * A token with a short expiration used for validating a user is authenticated. An expiresIn of 15m is used if not specified.
     * expiresIn should be set to the maximum amount of time a session is allowed to remain idle.
     */
    auth?: TokenOptions | undefined;
    /**
     * A token with a long expiration used to refresh auth tokens. An expiresIn of 3d is used if not specified.
     * expiresIn should be set to the maximum amount of time a user is allowed to be logged in for without re-authorizing.
     * These tokens should be persisted, and removed when the user logs out, ending their session and preventing new tokens
     * from being created. The {@link LoginOperations.storeRefreshToken } function is used to store the token when it's
     * created, and the {@link LoginOperations.invalidateRefreshToken } function is used when the user is logged out to
     * remove or mark the refresh token as invalid.
     */
    refresh?: TokenOptions | undefined;
};
/**
 * Functions related to logging in and out a user
 */
export type LoginOperations = {
    /**
     * load the user data by username
     */
    loadUserByUsername: loadUserByUsername;
    /**
     * Store a new refresh token
     */
    storeRefreshToken: storeRefreshToken;
    /**
     * Check if a refresh token is valid
     */
    checkRefreshTokenValid: checkRefreshTokenValid;
    /**
     * Invalidate the given refresh token
     */
    invalidateRefreshToken: invalidateRefreshToken;
    /**
     * HMAC Hash the password and salt
     */
    hashPassword: hashPassword;
    /**
     * Convert a {@link PersistedUser } to a {@link JwtUser }
     */
    userToJwtPayload: userToJwtPayload;
};
/**
 * A function to load the user data by username.
 * Implementation required if using any of {@link JwtCookieAuthorizer.basicAuthLogin } or {@link JwtCookieAuthorizer.basicAuthLoginMiddleware }
 */
export type loadUserByUsername = (username: string, request: AuthRequest, response: AuthResponse) => Promise<PersistedUser>;
/**
 * Store a newly created refresh token. Not called if refresh is disabled.
 * This function should store the cookie in persistent storage (i.e. sql db, redis, etc).
 *
 * To save space, you can store a hash of the token instead of the whole token value.
 *
 * You must also implement invalidateRefreshToken, which removes the refresh token
 * from the persistent storage. This prevents the user from further refreshing their auth token and logs the user out
 * everywhere.
 */
export type storeRefreshToken = (jwtUser: JwtUser, token: string) => Promise<void>;
/**
 * Check if the provided refresh token is valid to determine if it can be used to refresh an auth token.
 * Not called if refresh is disabled.
 *
 * If you would like to prevent calls to a datastore, have this function return true without any checks.
 *
 * Ideally, this should check in the data store whether this token is valid. This effectively makes this jwt authorizer
 * a stateful session, with the primary difference being that calls between refreshes don't need to hit a session store
 * to check if the session is valid. At a large scale, this will vastly reduce the amount of calls being made to a centralized
 * session store.
 *
 * The token is validated before this is called.
 */
export type checkRefreshTokenValid = (jwtUser: JwtUser, token: string) => Promise<void>;
/**
 * Remove a refresh token from persistent storage or otherwise mark it invalid. Not called if refresh is disabled.
 */
export type invalidateRefreshToken = (jwtUser: JwtUser, token: string) => Promise<void>;
/**
 * Hash the given password and salt. Uses sha512 hash from crypto package by default.
 */
export type hashPassword = (password: string, salt: string) => Promise<string>;
/**
 * Map a user to the jwt payload when a token is created.
 */
export type userToJwtPayload = (user: PersistedUser) => Promise<JwtUser>;
/**
 * Options related to locking a user
 */
export type LockingOptions = {
    /**
     * Maximum number of login attempts to allow before locking the user. Defaults to 10.
     */
    maxFailedLogins?: number | undefined;
    /**
     * Number of seconds to lock the user after reaching the max failed attempts. Defaults to 10 minutes.
     */
    lockSeconds?: number | undefined;
    /**
     * Set the user's lock status
     */
    setLockStatus: setLockStatus;
};
/**
 * Update the user when it's lock status is changed.
 * This function should persist the changes to the user.
 */
export type setLockStatus = (userLockEvent: UserLockEvent) => Promise<void>;
/**
 * Options passed to create a new JwtCookieAuthorizer
 * TokenOptions properties are the defaults used if values are not passed for specific tokens, except for cookieName
 */
export type AuthorizerOptions = {
    /**
     * Operations for login and refresh
     */
    login: LoginOperations;
    /**
     * Options related to locking users, locking is disabled if this is not set
     */
    locking?: LockingOptions | undefined;
    /**
     * Token configurations
     */
    tokens?: Tokens | undefined;
    /**
     * Whether refresh tokens are enabled.
     * This is true by default and the corresponding refresh methods must be provided on the LoginOperations.
     *
     * If this is disabled, it will disable the ability to log out users, and will prevent refresh tokens from being created.
     *
     * It is not recommended to disable refresh for anything important, but is fine for toy apps and non-critical applications
     */
    refreshEnabled?: boolean | undefined;
    /**
     * The default secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided
     */
    secret?: (string | Buffer) | undefined;
    /**
     * The default keys used to sign and verify JWTs, cannot be set if secret is provided
     */
    keys?: JwtKeys | undefined;
    /**
     * The default options passed to sign when creating a token.
     * Recommended to pass issuer and expiresIn at minimum.
     * See https://www.npmjs.com/package/jsonwebtoken
     * example: {issuer: 'my-app', expiresIn: '3m'}
     */
    signOptions?: object | undefined;
    /**
     * The default options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
     */
    verifyOptions?: object | undefined;
    /**
     * The default configuration options to pass cookie.serialize See https://www.npmjs.com/package/cookie
     */
    cookieConfig?: object | undefined;
};
/**
 * A middleware function
 */
export type middleware = (req: object, res: object, next: () => void) => void;
//# sourceMappingURL=index.d.ts.map