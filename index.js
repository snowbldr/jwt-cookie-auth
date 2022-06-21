import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import cookie from 'cookie'
import { promisify } from 'util'

const signJwt = promisify(jwt.sign)
const verifyJwt = promisify(jwt.verify)

export class User {
  /**
   * The user's unique name
   * @type string
   */
  username
  /**
   * Roles assigned to the user
   * @type Array.<string>=
   */
  roles

  /**
   * @param {{ username: string, roles: Array.<string>= }} opts
   */
  constructor ({ username, roles }) {
    this.username = username
    this.roles = roles
  }
}

/**
 * Minimal JWT user data
 */
export class JwtUser extends User { //eslint-disable-line
  /**
   * The user's unique name, synonym for username
   * @type string
   */
  sub

  /**
   * @param {{ username: string, roles: Array.<string>=, sub: string}} opts
   */
  constructor ({ username, roles, sub }) {
    super({ username, roles })
    this.sub = sub
  }
}

/**
 * Minimal data for a persisted user capable of logging in
 */
export class PersistedUser extends User { //eslint-disable-line
  /**
   * A hash of the user's password and their salt
   * @type string
   */
  passwordHash
  /**
   * A random unique string used to make the same password hash to a different value and prevent identifying shared passwords based on the hash
   * @type string
   */
  salt
  /**
   * The number of failed login attempts so far
   * @type number=
   */
  failedLogins
  /**
   * The point in time when this user became locked
   * @type Date=
   */
  lockedAt

  /**
   *
   * @param {{username: string, roles: Array.<string>, passwordHash: string, salt: string, failedLogins: number=, lockedAt: Date=}} opts
   */
  constructor ({ username, roles, passwordHash, salt, failedLogins, lockedAt }) {
    super({ username, roles })
    this.passwordHash = passwordHash
    this.salt = salt
    this.failedLogins = failedLogins
    this.lockedAt = lockedAt
  }
}

export class UserLockEvent { //eslint-disable-line
  /**
   * The user's unique name
   * @type {string}
   */
  username
  /**
   * The action that triggered the {@link AuthorizerOptions.setLockStatus} function, one of ('failedAttempt', 'locked', 'unlocked')
   * @type {string}
   */
  action
  /**
   * The number of failed login attempts so far
   * @type {number}
   */
  failedLogins
  /**
   * The point in time when this user became locked
   * @type {Date=}
   */
  lockedAt

  /**
   *
   * @param {{username: string, action: string, failedLogins: number, lockedAt: Date=}} opts
   */
  constructor ({ username, action, failedLogins, lockedAt }) {
    this.username = username
    this.action = action
    this.failedLogins = failedLogins
    this.lockedAt = lockedAt
  }
}

export class LoginResult { //eslint-disable-line
  /**
   * The user data that was encoded in the JWTs
   * @type JwtUser
   */
  jwtUser
  /**
   * A JWT token to be used for authentication
   * @type string
   */
  authToken
  /**
   * A cookie containing the authToken
   * @type string
   */
  authCookie
  /**
   * A JWT token to be used for obtaining new auth tokens
   * only provided if refresh is enabled
   * @type string=
   */
  refreshToken
  /**
   * A cookie containing the authToken
   * only provided if refresh is enabled
   * @type string=
   */
  refreshCookie

  /**
   *
   * @param {{jwtUser: JwtUser, authToken: string, authCookie: string, refreshToken: string=, refreshCookie: string=}} opts
   */
  constructor ({ jwtUser, authToken, authCookie, refreshToken, refreshCookie }) {
    this.jwtUser = jwtUser
    this.authToken = authToken
    this.authCookie = authCookie
    this.refreshToken = refreshToken
    this.refreshCookie = refreshCookie
  }
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
  // private to prevent secrets and keys from being read
  /**
   * @type AuthorizerOptions
   */
  #config

  /**
   * @param {AuthorizerOptions} authorizerOptions Options to configure the authorizer
   */
  constructor (authorizerOptions) {
    const config = {}
    config.refreshEnabled = typeof authorizerOptions.refreshEnabled === 'boolean' ? authorizerOptions.refreshEnabled : true
    config.login = buildLoginConfig(authorizerOptions.login, config.refreshEnabled)
    config.locking = buildLockingConfig(authorizerOptions.locking)
    config.tokens = {}
    authorizerOptions.tokens = authorizerOptions.tokens ?? {}
    for (const token of ['auth', 'refresh']) {
      config.tokens[token] = buildTokenConfig(token, authorizerOptions.tokens[token] || {}, authorizerOptions)
    }
    this.#config = config
  }

  /**
   * @return {middleware} A middleware that will authorize the request using the provided authorizer
   */
  basicAuthLoginMiddleware () {
    return (req, res, next) =>
      this.basicAuthLogin(req, res)
        .then(() => next())
        .catch(e => handleHttpError(res, e, next))
  }

  /**
   * Create a new middleware function that will exchange basic auth for a jwt token or will validate an existing jwt
   *
   * @return {middleware} A middleware that will authorize the request using this authorizer
   */
  authorizeMiddleware () {
    return (req, res, next) => {
      this.verifyAuth(req, res)
        .then(() => next())
        .catch(e => handleHttpError(res, e, next))
    }
  }

  /**
   * Create a new middleware function that will exchange a valid jwt for a newer valid jwt
   * @param {boolean} reloadUser Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data
   * @return {middleware} A middleware to refresh jwt token cookies
   */
  refreshAuthMiddleware (reloadUser = false) {
    if (!this.#config.refreshEnabled) {
      throw new Error('Refresh is disabled for this authorizer')
    }
    return (req, res, next) =>
      this.refreshAuthCookie(req, res, reloadUser)
        .then(() => next())
        .catch(e => handleHttpError(res, e, next))
  }

  /**
   * Create a middleware that will log out the user when called
   * @return {middleware}
   */
  logoutMiddleware () {
    return (req, res, next) => {
      this.logout(req, res)
        .then(() => next())
        .catch(e => handleHttpError(res, e, next))
    }
  }

  /**
   * Attempt to log the user in and create a new jwt token
   * @param {PersistedUser} user The user to log in
   * @param {string} password The plain text password to log the user in with
   * @return {LoginResult}
   * @throws {UnauthorizedError}
   */
  async login (user, password) {
    if (!user) {
      throw new UnauthorizedError('Login Failed')
    }

    if (this.#config.locking && user.lockedAt && new Date().getTime() < user.lockedAt.getTime() + (this.#config.locking.lockSeconds * 1000)) {
      throw new UnauthorizedError('Your user is locked, try again later.')
    }
    if (!user.passwordHash) {
      throw new UnauthorizedError('Login Failed')
    }

    const incoming = await this.#config.login.hashPassword(password, user.salt)

    if (incoming !== user.passwordHash) {
      if (this.#config.locking) {
        if (typeof user.failedLogins !== 'number') {
          user.failedLogins = 0
        }
        if (user.failedLogins >= this.#config.locking.maxFailedLogins) {
          await this.#config.locking.setLockStatus(new UserLockEvent({
            username: user.username,
            failedLogins: user.failedLogins + 1,
            lockedAt: new Date(),
            action: 'locked'
          }))
          throw new UnauthorizedError('Too many failed attempts, user locked.')
        }
        await this.#config.locking.setLockStatus(new UserLockEvent({
          username: user.username,
          failedLogins: user.failedLogins + 1,
          lockedAt: null,
          action: 'failedAttempt'
        }))
      }
      throw new UnauthorizedError('Login Failed')
    }

    if ((this.#config.locking && user.lockedAt) || user.failedLogins > 0) {
      await this.#config.locking.setLockStatus(new UserLockEvent({
        username: user.username,
        failedLogins: 0,
        lockedAt: null,
        action: 'unlocked'
      }))
    }

    const jwtUser = await this.#config.login.userToJwtPayload(user)
    const authToken = await createJwtToken(jwtUser, this.#config.tokens.auth)
    const result = {
      jwtUser,
      authToken,
      authCookie: createTokenCookie(this.#config.tokens.auth, authToken)
    }
    if (this.#config.refreshEnabled) {
      result.refreshToken = await createJwtToken(jwtUser, this.#config.tokens.refresh)
      result.refreshCookie = createTokenCookie(this.#config.tokens.refresh, result.refreshToken)
      await this.#config.login.storeRefreshToken(jwtUser, result.refreshToken)
    }
    return new LoginResult(result)
  }

  /**
   * Verify the provided jwt cookie and set the user on the request to the parser user in the jwt
   * @param {AuthRequest} req The incoming request
   * @param {AuthResponse} res The outgoing response
   * @return {Promise<JwtUser>}
   * @throws {UnauthorizedError}
   */
  async verifyAuth (req, res) {
    return this.#verifyRequest(req, res, this.#config.tokens.auth)
  }

  /**
   * Log the current user out by deleting their cookies and calling invalidateRefreshToken
   * @param {AuthRequest} req The current request
   * @param {AuthResponse} res The current response
   * @return {Promise<void>}
   */
  async logout (req, res) {
    if (!res.loggedOut) {
      const cookiesToDelete = [this.#config.tokens.auth.cookieName]
      if (this.#config.refreshEnabled) {
        cookiesToDelete.push(this.#config.tokens.refresh.cookieName)
      }
      deleteCookies(res, ...cookiesToDelete)
      if (this.#config.refreshEnabled) {
        const refreshToken = this.getCookieValue(req, this.#config.tokens.refresh.cookieName)
        if (refreshToken) {
          await this.#config.login.invalidateRefreshToken(jwt.decode(refreshToken, {}), refreshToken)
        }
      }
      res.loggedOut = true
    }
  }

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
  async refreshAuthCookie (req, res, reloadUser = false) {
    if (!this.#config.refreshEnabled) {
      throw new Error('Refresh is disabled for this authorizer')
    }
    await this.#logoutUnauthorized(req, res, async () => {
      const tokenOptions = this.#config.tokens.auth
      let authUser = await this.#verifyRequest(req, res, tokenOptions)
      const refreshUser = await this.#verifyRequest(req, res, this.#config.tokens.refresh)
      const refreshToken = this.getCookieValue(req, this.#config.tokens.refresh.cookieName)
      const refreshTokenValid = await this.#config.login.checkRefreshTokenValid(refreshUser, refreshToken)
      if (refreshTokenValid !== true) {
        throw new UnauthorizedError('Refresh token invalid')
      }
      if (reloadUser) {
        const persistedUser = await this.#config.login.loadUserByUsername(authUser.username, req, res)
        authUser = await this.#config.login.userToJwtPayload(persistedUser)
      }
      const authToken = await createJwtToken(removeConflictingJwtFields(authUser, tokenOptions.signOptions), tokenOptions)
      req.user = authUser
      setCookies(res, createTokenCookie(tokenOptions, authToken))
    })
  }

  /**
   * Log the user in using a basic auth header
   * @param {AuthRequest} req The current request with a headers object containing the request headers
   * @param {AuthResponse} res The current response to set the cookies on
   * @throws {UnauthorizedError}
   */
  async basicAuthLogin (req, res) {
    const loadUserByUsername = this.#config.login.loadUserByUsername
    ensureFn(this.#config.login, 'loadUserByUsername', false)
    await this.#logoutUnauthorized(req, res, async () => {
      const authHeader = req.headers.authorization
      if (authHeader) {
        const { username, password } = this.parseBasicAuthHeader(authHeader)
        const {
          authCookie,
          refreshCookie,
          jwtUser
        } = await this.login(await loadUserByUsername(username, req, res), password)
        const cookiesToSet = [authCookie]
        if (refreshCookie) cookiesToSet.push(refreshCookie)
        setCookies(res, ...cookiesToSet)
        req.user = jwtUser
      } else {
        throw new UnauthorizedError('Authorization not provided')
      }
    })
  }

  /**
   * Get a cookie's value from the request
   * @param {AuthRequest} req The current request
   * @param {string} cookieName The cookie's value to get
   * @return {string}
   */
  getCookieValue (req, cookieName) {
    return getCookies(req)[cookieName]
  }

  /**
   * @param {string} authHeader The authorization header value from the request
   * @return {{password: string, username: string}}
   * @throws {UnauthorizedError}
   */
  parseBasicAuthHeader (authHeader) {
    if (!authHeader) {
      throw new UnauthorizedError()
    }
    const authParts = authHeader.split(' ')
    if (authParts[0].toLowerCase() !== 'basic') {
      throw new UnauthorizedError('Basic Authorization header must be used')
    }
    const userPass = Buffer.from(authParts[1], 'base64').toString().split(':')
    return {
      username: userPass[0],
      password: userPass[1]
    }
  }

  /**
   * Verify the provided jwt cookie and set request.user from the decoded jwt payload
   * @param {AuthRequest} req The incoming request
   * @param {AuthResponse} res The outgoing response
   * @param {TokenOptions} tokenOptions The token options to use to verify the token
   * @return {Promise<JwtUser>}
   * @throws {UnauthorizedError}
   */
  async #verifyRequest (req, res, tokenOptions) {
    return this.#logoutUnauthorized(req, res, async () => {
      req.user = await verifyJwtToken(this.getCookieValue(req, tokenOptions.cookieName), tokenOptions)
      return req.user
    })
  }

  /**
   * Logout the user if an unauthorized error is thrown
   * @param {AuthRequest} req The incoming request
   * @param {AuthResponse} res The outgoing response
   * @param {function():*}fn The function to run and listen for {@link UnauthorizedError}
   * @return {Promise<*>} The return value from fn
   */
  async #logoutUnauthorized (req, res, fn) {
    try {
      return await fn()
    } catch (e) {
      if (e instanceof UnauthorizedError) {
        await this.logout(req, res)
      }
      throw e
    }
  }
}

/**
 * Check whether the userRoles contains at least one of the requiredRoles
 * @param {string[]} userRoles An array of the roles the user is assigned
 * @param {...string} requiredRoles An array of the roles the user must have one of
 * @return {boolean}
 */
export const hasAnyRole = (userRoles, ...requiredRoles) => {
  if (!Array.isArray(requiredRoles) || !Array.isArray(userRoles)) {
    throw new Error('requiredRoles and userRoles must be an array')
  }
  for (const role of requiredRoles) {
    if (userRoles.includes(role)) {
      return true
    }
  }
  return false
}

/**
 * Check whether the userRoles contains all the requiredRoles
 * @param {string[]} userRoles An array of the roles the user is assigned
 * @param {...string} requiredRoles An array of the roles the user must have all of
 * @return {boolean}
 */
export const hasAllRoles = (userRoles, ...requiredRoles) => {
  if (!Array.isArray(requiredRoles) || !Array.isArray(userRoles)) {
    throw new Error('requiredRoles and userRoles must be an array')
  }
  for (const role of requiredRoles) {
    if (!userRoles.includes(role)) {
      return false
    }
  }
  return true
}

/**
 * Create a middleware to validate the current user has any of the specified roles
 * @param {...string} requiredRoles The roles the user must have one of
 * @return {middleware} a new middleware function that reads the user's roles from req.user.roles and validates the user has any of required roles
 */
export const hasAnyRoleMiddleware = (...requiredRoles) => {
  return (req, res, next) => {
    if (hasAnyRole(req.user.roles, ...requiredRoles)) {
      return next()
    } else {
      return endRes(res, 403, 'Forbidden')
    }
  }
}

/**
 * Create a middleware to validate the current user has all the required roles
 * @param {...string} requiredRoles The roles the user must have all of
 * @return {middleware} a new middleware function that reads the user's roles form req.user.roles and validates the user has all the required roles
 */
export const hasAllRolesMiddleware = (...requiredRoles) => {
  return (req, res, next) => {
    if (hasAllRoles(req.user.roles, ...requiredRoles)) {
      return next()
    } else {
      return endRes(res, 403, 'Forbidden')
    }
  }
}

/**
 * Create a jwt cookie
 * @param {TokenOptions} tokenOptions The options for the cookie to make
 * @param {string} jwtToken The jwt token to create a cookie for
 * @returns {String} The serialized jwt cookie
 */
function createTokenCookie (tokenOptions, jwtToken) {
  return cookie.serialize(tokenOptions.cookieName, jwtToken, {
    maxAge: 60 * 60 * 24 * 3, // 3 days
    secure: true,
    ...valOrDefault(tokenOptions.cookieConfig, {}),
    // Don't allow authorization cookies to be read by js
    httpOnly: true
  })
}

/**
 * Create a hmac sha512 hash of the given value and salt
 * @param {string} value The value to hash
 * @param {string} salt A salt to use to create the hmac
 * @return {string} A base64 hash of the value
 */
export function createSha512Hmac (value, salt) {
  const hash = crypto.createHmac('sha512', String(salt))
  hash.update(value)
  return hash.digest('base64')
}

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
  constructor (statusCode, statusMessage, body) {
    super(body)
    this.statusCode = statusCode
    this.statusMessage = statusMessage
    this.body = body ?? ''
  }
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
  constructor (body, cause) {
    super(401, 'Unauthorized', body)
    if (cause) this.stack += `\n${cause.stack}`
  }
}

/**
 * Set cookies on the response. The cookies should be serialized strings.
 * If there are existing values for set-cookie, they will not be overridden.
 *
 * @param {AuthResponse} res The response object to set the cookies on
 * @param {...string} cookies The serialized cookies to add to the set-cookie header
 */
export function setCookies (res, ...cookies) {
  const getter = res.getHeader || res.get
  let cookieArray = getter.call(res, 'set-cookie') || []
  if (!Array.isArray(cookieArray)) {
    cookieArray = [cookieArray]
  }
  cookieArray.push(...cookies)
  const setter = res.setHeader || res.set
  setter.call(res, 'Set-Cookie', cookieArray)
}

/**
 * Delete the user's cookies.
 *
 * @param {AuthResponse} res The response object to set the cookies on
 * @param {...string} cookieNames The names of the cookies to add to the set-cookie header
 */
export function deleteCookies (res, ...cookieNames) {
  setCookies(res, ...cookieNames.map(name => cookie.serialize(name, '', { expires: new Date(1) })))
}

/**
 * Get the parsed cookies from the request
 * @param {AuthRequest} req The request object to get cookies from
 * @return {object} An object containing the cookies by name
 */
export function getCookies (req) {
  if (typeof req.cookies === 'object') {
    return req.cookies
  } else if (req.headers?.cookie) {
    const cookies = cookie.parse(req.headers.cookie)
    if (!req.cookies) {
      req.cookies = cookies
    }
    return cookies
  } else {
    return {}
  }
}

/**
 * Verify the provided jwt cookie and set the user on the request to the parser user in the jwt
 * @param {string} jwtToken The encoded JWT token
 * @param {TokenOptions} tokenOptions Options for verifying the token
 */
async function verifyJwtToken (jwtToken, tokenOptions) {
  if (jwtToken) {
    try {
      return await verifyJwt(jwtToken, getVerifySecret(tokenOptions), tokenOptions.verifyOptions)
    } catch (e) {
      throw new UnauthorizedError('Invalid Jwt', e)
    }
  } else {
    throw new UnauthorizedError('Jwt not provided')
  }
}

/**
 * @param {object} jwtInfo The user info to encode in the jwt
 * @param {TokenOptions} tokenOptions Options to use for creating the token
 * @return {Promise<string>}
 */
async function createJwtToken (jwtInfo, tokenOptions) {
  return signJwt(jwtInfo, getSignSecret(tokenOptions), tokenOptions.signOptions)
}

/**
 * Validate the provided login options and construct a config with defaults
 * @param {LoginOperations} input
 * @param {boolean} refreshEnabled
 * @returns {LoginOperations}
 */
function buildLoginConfig (input, refreshEnabled) {
  const out = {}
  out.hashPassword = valOrDefault(ensureFn(input, 'hashPassword', true), createSha512Hmac)
  out.userToJwtPayload = valOrDefault(ensureFn(input, 'userToJwtPayload', true), user => ({
    sub: user.username,
    username: user.username,
    roles: user.roles || []
  }))
  out.loadUserByUsername = ensureFn(input, 'loadUserByUsername', true)
  if (refreshEnabled) {
    out.storeRefreshToken = ensureFn(input, 'storeRefreshToken', false)
    out.invalidateRefreshToken = ensureFn(input, 'invalidateRefreshToken', false)
    out.checkRefreshTokenValid = ensureFn(input, 'checkRefreshTokenValid', false)
  }
  return out
}

/**
 * Validate the provided locking options and construct a config with defaults
 * @param {LockingOptions} input
 * @returns {LockingOptions=}
 */
function buildLockingConfig (input) {
  if (!input) return null
  const out = {}
  out.maxFailedLogins = valOrDefault(ensureNumber(input, 'maxFailedLogins', true), 10)
  out.lockSeconds = valOrDefault(ensureNumber(input, 'lockSeconds', true), 600)
  out.setLockStatus = ensureFn(input, 'setLockStatus')
  return out
}

/**
 * Validate the provided token options and construct a config object with defaults
 * @param {string} name
 * @param {TokenOptions} input
 * @param {TokenOptions} baseOptions
 * @return {TokenOptions}
 */
function buildTokenConfig (name, input, baseOptions) {
  const out = {}
  out.secret = input.secret || baseOptions.secret
  if (input.keys || baseOptions.keys) {
    out.keys = mergeConfig(baseOptions.keys, input.keys)
  }
  out.signOptions = mergeConfig(baseOptions.signOptions, input.signOptions)
  out.verifyOptions = mergeConfig(baseOptions.verifyOptions, input.verifyOptions)
  out.cookieConfig = mergeConfig(baseOptions.cookieConfig, input.cookieConfig)
  out.cookieName = valOrDefault(input.cookieName, `jwt-${name}`)

  const algorithm = out.secret ? 'HS512' : 'RS512'
  out.signOptions.algorithm = valOrDefault(out.signOptions.algorithm, algorithm)
  out.verifyOptions.algorithm = valOrDefault(out.verifyOptions.algorithm, [algorithm])

  const defaultTimeout = name === 'refresh' ? '3d' : '15m'
  out.signOptions.expiresIn = valOrDefault(out.signOptions.expiresIn, defaultTimeout)

  ensureStringOrBuffer(input, 'secret', true)
  if (out.keys) {
    ensureObject(out, 'keys')
    ensureStringOrBuffer(out.keys, 'public')
    ensureStringOrBuffer(out.keys, 'private', true)
    if (!out.keys.private) {
      console.info(`keys.private not provided, will not be able to create ${name} tokens`)
    }
  }
  if (out.cookieConfig.httpOnly === false) {
    throw new Error('cookieConfig.httpOnly must be true')
  }
  if (out.secret && out.keys) {
    throw new Error('You cannot set both secret and keys for each token')
  }
  if (!out.secret && (!out.keys || typeof out.keys !== 'object')) {
    throw new Error('You must specify either secret or keys for each token')
  }
  return out
}

function mergeConfig (...objects) {
  const res = {}
  for (const obj of objects) {
    Object.assign(res, obj || {})
  }
  return res
}

function handleHttpError (res, e, next) {
  if (e instanceof HttpStatusError) {
    res.statusCode = e.statusCode
    res.statusMessage = e.statusMessage
    next(e)
  } else {
    next(e)
  }
}

/**
 * @param {TokenOptions} options
 * @return {string|Buffer}
 */
function getSignSecret (options) {
  return options.keys?.private || options.secret
}

/**
 * @param {TokenOptions} options
 * @return {string|Buffer}
 */
function getVerifySecret (options) {
  return options.keys?.public || options.secret
}

function endRes (res, statusCode, message) {
  res.statusCode = statusCode
  res.statusMessage = message
  return res.end()
}

/**
 * Ensure a property of an object is of the specified type
 * @param obj The object whose property to verify
 * @param prop The property to verify
 * @param {string} type The type the property must be (compared to the result of typeof on the property value)
 * @param optional Whether the property is optional, throws an error if false
 * @return {*}
 */
function ensureType (obj, prop, type, optional = false) {
  if (!optional && !obj[prop]) {
    throw new Error(`${prop} must be defined`)
  }
  // eslint-disable-next-line valid-typeof
  if (obj[prop] && typeof obj[prop] !== type) {
    throw new Error(`${prop} must be of type ${type}`)
  }
  return obj[prop]
}

const ensureFn = (obj, prop, optional = false) => ensureType(obj, prop, 'function', optional)
const ensureNumber = (obj, prop, optional = false) => ensureType(obj, prop, 'number', optional)
const ensureObject = (obj, prop, optional = false) => ensureType(obj, prop, 'object', optional)
const ensureStringOrBuffer = (obj, prop, optional = false) => {
  if (!optional && !obj[prop]) {
    throw new Error(`${prop} must be defined`)
  }
  if (obj[prop] && typeof obj[prop] !== 'string' && !(obj[prop] instanceof Buffer)) {
    throw new Error(`${prop} must be of a string or a Buffer`)
  }
  return obj[prop]
}
const valOrDefault = (value, defaultValue) => typeof value === typeof defaultValue ? value : defaultValue

/**
 * Some jwt fields can be specified in both the payload and the options
 * jsonwebtoken will throw an error if specified in both
 * This function makes the specified options win vs the payload
 *
 * This is only relevant when refreshing an auth token
 *
 * The sub field is not checked, and should only be set on the user and should not be set in the options
 *
 * @param {JwtUser} payload The payload to compare
 * @param {object} options The jsonwebtoken options to compare
 * @return {JwtUser} The payload with any conflicting jwt fields removed, they will be re-created after signing as specified in the options.
 */
function removeConflictingJwtFields (payload, options) {
  const result = { ...payload }
  if (options.expiresIn && result.exp) {
    delete result.exp
  }
  if (options.notBefore && result.nbf) {
    delete result.nbf
  }
  if (options.audience && result.aud) {
    delete result.aud
  }
  if (options.issuer && result.iss) {
    delete result.iss
  }
  return result
}
