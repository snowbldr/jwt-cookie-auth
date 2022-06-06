import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import cookie from 'cookie'
import { promisify } from 'util'

const signJwt = promisify(jwt.sign)
const verifyJwt = promisify(jwt.verify)

/**
 * @typedef {object} AuthResponse Minimal required properties of a response object as used by JwtCookieAuthorizer
 * @interface
 * @property {function(string)} [getHeader] return the value of a header
 * @property {function(string)} [get] return the value of a header (available in frameworks like express)
 * @property {function(string)} [setHeader] set the value of a header
 * @property {function(string)} [set] set the value of a header (available in frameworks like express)
 * @property {number} statusCode Used to set the HTTP response status code
 * @property {string} statusMessage Used to set the HTTP response status message
 * @property {function} end End the current response
 */

/**
 * @typedef {object} AuthRequest Minimal required properties of a request object as used by JwtCookieAuthorizer
 * @interface
 * @property {object} [cookies] Parsed cookies received on the request, cookies are parsed from the header if not available
 * @property {object} headers Headers received on the request
 * @property {object} [user] The user object retrieved from the jwt
 *
 */

/**
 * @typedef {object} JwtKeys Keys used to sign and verify JWTs
 * @typedef {!string|!Buffer} private The private key passed to sign from https://www.npmjs.com/package/jsonwebtoken
 * @typedef {!string|!Buffer} public The public key passed to sign from https://www.npmjs.com/package/jsonwebtoken
 */

/**
 * @typedef {object} TokenOptions
 * @property {!String|!Buffer} [secret] The secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided
 * @property {JwtKeys} [keys] An object containing keys used to sign and verify JWTs, cannot be set if secret is provided
 * @property {object} [signOptions] Options passed to {@link jwt.sign} when creating a token.
 *        Recommended to pass issuer and expiresIn at minimum.
 *        See https://www.npmjs.com/package/jsonwebtoken
 *        example: {issuer: 'my-app', expiresIn: '3m'}
 * @property {object} [verifyOptions] Options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
 * @property {string} [cookieName] The cookie name to store the token into, defaults to jwt-${name} where name is either auth or refresh
 * @property {object} [cookieConfig] Configuration options to pass cooke.serialize See https://www.npmjs.com/package/cookie
 */

/**
 * @typedef {object} Tokens Options for the tokens this verified deals with. Cookie names default to jwt-${tokenName}
 * @property {TokenOptions} [auth] A token with a short expiration used for validating a user is authenticated. An expiresIn of 5m is used if not specified.
 *        expiresIn should be set to the maximum amount of time a session is allowed to remain idle.
 * @property {TokenOptions} [refresh] A token with a long expiration used to refresh auth tokens. An expiresIn of 1d is used if not specified.
 *        expiresIn should be set to the maximum amount of time a user is allowed to be logged in for without re-authorizing.
 *        These tokens should be persisted, and removed when the user logs out, ending their session and preventing new tokens
 *        from being created. The {@link AuthorizerOptions.storeRefreshToken} function is used to store the token when it's
 *        created, and the {@link AuthorizerOptions.invalidateRefreshToken} function is used when the user is logged out to
 *        remove or mark the refresh token as invalid.
 */

/**
 * @typedef User A user capable of logging in, identifiable by username
 * @property {string} username The user's unique name
 * @property {string[]} [roles] Roles assigned to the user
 */

/**
 * @typedef {User} JwtUser Minimal JWT user data
 * @property {string} sub The user's unique name, synonym for username
 */

/**
 * @typedef {User} PersistedUser Minimal data for a persisted user capable of logging in
 * @property {string} passwordHash A hash of the user's password and their salt
 * @property {string} salt A random unique string used to make the same password hash to a different value and prevent identifying shared passwords based on the hash
 * @property {number} [failedLogins] The number of failed login attempts so far
 * @property {Date} [lockedAt] The point in time when this user became locked
 */

/**
 * @typedef {object} UserLockEvent Minimal user data for a persisted user record
 * @property {string} username The user's unique name
 * @property {('failedAttempt', 'locked', 'unlocked')} action The action that triggered the {@link AuthorizerOptions.setLockStatus} function
 * @property {number} [failedLogins] The number of failed login attempts so far
 * @property {Date} lockedAt The point in time when this user became locked
 */

/**
 * @typedef {object} LoginOptions Options related to logging in and out a user
 * @property {function(password: string,salt: string): Promise<string>} [hashPassword] Hash the given password and salt. Uses sha512 hash from crypto package by default.
 * @property {function(user: PersistedUser): Promise<JwtUser>} [userToJwtPayload] Map a user to the jwt payload when a token is created.
 * @property {function(string, AuthRequest, AuthResponse): Promise<PersistedUser>} [loadUserByUsername] A function to load the user data by username.
 *      Required if using any of {@link JwtCookieAuthorizer.basicAuthLogin} or {@link JwtCookieAuthorizer.basicAuthLoginMiddleware}
 * @property {function(jwtUser: JwtUser, token: string): Promise<boolean>} checkRefreshTokenValid Check if the provided refresh token is valid to determine if it can be used to refresh an auth token
 * @property {function(jwtUser: JwtUser, token: string): Promise<void>} storeRefreshToken Store a newly created refresh token.
 *      This function should store the cookie in persistent storage (i.e. sql db, redis, etc)
 *      A corresponding function should be passed to the logout middleware that removes the refresh token
 *      from the persistent storage, which prevents the user from further refreshing their auth token.
 * @property {function(jwtUser: JwtUser, token: string): Promise<void>} invalidateRefreshToken Remove a refresh token from persistent storage or otherwise mark it invalid
 */

/**
 * @typedef {object} LockingOptions Options related to locking a user
 * @property {Number} [maxFailedLogins] Maximum number of login attempts to allow before locking the user. Defaults to 10.
 * @property {Number} [lockSeconds] Number of seconds to lock the user after reaching the max failed attempts. Defaults to 10 minutes.
 * @property {function(UserLockEvent): Promise<void>} setLockStatus Update the user when it's lock status is changed. Required if enableLocking is true.
 *      This function should persist the changes to the user.
 */

/**
 * @typedef {TokenOptions} AuthorizerOptions Options passed to create a new JwtCookieAuthorizer
 * TokenOptions properties are the defaults used if values are not passed for specific tokens, except for cookieName
 * @property {Tokens} [tokens] Options for creating and verifying tokens
 * @property {LoginOptions} [login] Options related to logging in and out a user
 * @property {LockingOptions} [locking] Options related to locking a user, locking is disabled if not passed
 */

/**
 * An object that handles creating and authenticated JWTs
 */
export class JwtCookieAuthorizer {
  //private to prevent secrets and keys from being read
  /**
   * @type AuthorizerOptions
   */
  #config

  /**
   * @param {AuthorizerOptions} authorizerOptions Options to configure the authorizer
   */
  constructor (authorizerOptions) {
    this.#config = JwtCookieAuthorizer.#buildConfig(authorizerOptions)
  }

  /**
   * @return {(function(*, *, *): void)|*} A middleware that will authorize the request using the provided authorizer
   */
  basicAuthLoginMiddleware () {
    return (req, res, next) =>
      this.basicAuthLogin(req, res)
        .then(next)
        .catch(e => handleHttpError(res, e, next))
  }

  /**
   * Create a new middleware function that will exchange basic auth for a jwt token or will validate an existing jwt
   *
   * @return {(function(*, *, *): void)|*} A middleware that will authorize the request using this authorizer
   */
  authorizeMiddleware () {
    return (req, res, next) => {
      this.verifyAuth(req, res)
        .then(next)
        .catch(e => handleHttpError(res, e, next))
    }
  }

  /**
   * Create a new middleware function that will exchange a valid jwt for a newer valid jwt
   * @param relogUser Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data
   * @return {(function(*, *, *): void)|*} A middleware to refresh jwt token cookies
   */
  refreshAuthMiddleware (relogUser = false) {
    return (req, res, next) =>
      this.refreshAuthCookie(req, res, relogUser)
        .then(next)
        .catch(e => handleHttpError(res, e, next))
  }

  /**
   * Create a middleware that will log out the user when called
   * @return {(function(*, *, *): void)|*}
   */
  logoutMiddleware () {
    return (req, res, next) => {
      this.logout(req, res)
        .then(next)
        .catch(e => handleHttpError(res, e, next))
    }
  }

  /**
   * @typedef {object} LoginResponse
   * @property {JwtUser} jwtUser The user data that was encoded in the JWTs
   * @property {string} authToken A JWT token to be used for authentication
   * @property {string} authCookie A cookie containing the authToken
   * @property {string} refreshToken A JWT token to be used for refresh auth tokens
   * @property {string} refreshCookie A cookie containing the authToken
   */

  /**
   * Attempt to log the user in and create a new jwt token
   * @param {PersistedUser} user The user to log in
   * @param {string} password The plain text password to log the user in with
   * @return {LoginResponse}
   * @throws {UnauthorizedError}
   */
  async login (user, password) {
    if (!user) {
      throw new UnauthorizedError('Login Failed')
    }

    if (this.#config.locking && user.lockedAt && new Date().getTime() < user.lockedAt.getTime() + ( this.#config.locking.lockSeconds * 1000 )) {
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
          await this.#config.locking.setLockStatus({
            username: user.username,
            failedLogins: user.failedLogins + 1,
            lockedAt: new Date(),
            action: 'locked'
          })
          throw new UnauthorizedError('Too many failed attempts, user locked.')
        }
        await this.#config.locking.setLockStatus({
          username: user.username,
          failedLogins: user.failedLogins + 1,
          lockedAt: null,
          action: 'failedAttempt'
        })
      }
      throw new UnauthorizedError('Login Failed')
    }

    if (this.#config.locking && user.lockedAt || user.failedLogins > 0) {
      await this.#config.locking.setLockStatus({
        username: user.username,
        failedLogins: 0,
        lockedAt: null,
        action: 'unlocked'
      })
    }

    const jwtUser = await this.#config.login.userToJwtPayload(user)
    const authToken = await createJwtToken(jwtUser, this.#config.tokens.auth)
    const refreshToken = await createJwtToken(jwtUser, this.#config.tokens.refresh)
    await this.#config.login.storeRefreshToken(jwtUser, refreshToken)

    return {
      authToken,
      refreshToken,
      authCookie: createTokenCookie(this.#config.tokens.auth, authToken),
      refreshCookie: createTokenCookie(this.#config.tokens.refresh, refreshToken),
      jwtUser
    }
  }

  /**
   * Verify the provided jwt cookie and set the user on the request to the parser user in the jwt
   * @param {AuthRequest} req The incoming request
   * @param {AuthResponse} res The outgoing response
   * @return {Promise<void>}
   * @throws {UnauthorizedError}
   */
  async verifyAuth (req, res) {
    await this.#verifyRequest(req, res, this.#config.tokens.auth)
  }

  /**
   * Log the current user out by deleting their cookies and calling invalidateRefreshToken
   * @param req The current request
   * @param res The current response
   * @return {Promise<void>}
   */
  async logout (req, res) {
    if (!res.loggedOut) {
      deleteCookies(res, ...Object.values(this.#config.tokens).map(t => t.cookieName))
      let refreshToken = this.getCookieValue(req, this.#config.tokens.refresh.cookieName)
      if (refreshToken) {
        await this.#config.login.invalidateRefreshToken(jwt.decode(refreshToken, {}), refreshToken)
      }
      res.loggedOut = true
    }
  }

  /**
   * Exchange a valid jwt token for a new one with a later expiration time
   * The request must contain a valid auth token and a valid refresh token to be accepted
   * You must refresh the auth cookie before either token expires to keep the session active
   * If either token is expired, the user must re-login
   * The new jwt is added as a cookie which overwrites the existing cookie
   * @param req The current request object
   * @param res The current response object
   * @param relogUser Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data
   * @return {Promise<void>}
   * @throws {UnauthorizedError}
   */
  async refreshAuthCookie (req, res, relogUser = false) {
    await this.#logoutUnauthorized(req, res, async () => {
      let authUser = await this.#verifyRequest(req, res, this.#config.tokens.auth)
      const refreshUser = await this.#verifyRequest(req, res, this.#config.tokens.refresh)
      const refreshToken = this.getCookieValue(req, this.#config.tokens.refresh.cookieName)
      let refreshTokenValid = await this.#config.login.checkRefreshTokenValid(refreshUser, refreshToken)
      if (refreshTokenValid !== true) {
        throw new UnauthorizedError('Refresh token invalid')
      }
      if (relogUser) {
        const persistedUser = await this.#config.login.loadUserByUsername(refreshUser.username, req, res)
        authUser = await this.#config.login.userToJwtPayload(persistedUser)
      }
      const authToken = await createJwtToken(authUser, this.#config.tokens.auth)
      req.user = authUser
      setCookies(res, createTokenCookie(this.#config.tokens.auth, authToken))
    })
  }

  /**
   * @param {AuthRequest} req The current request with a headers object containing the request headers
   * @param {AuthResponse} res The current response to set the cookies on
   * @throws {UnauthorizedError}
   */
  async basicAuthLogin (req, res) {
    await this.#logoutUnauthorized(req, res, async () => {
      const loadUserByUsername = this.#config.login.loadUserByUsername
      ensureFn(this.#config.login, 'loadUserByUsername', false)
      const authHeader = req.headers.authorization
      if (authHeader) {
        const { username, password } = this.parseBasicAuthHeader(authHeader)
        const {
          authCookie,
          refreshCookie,
          jwtUser
        } = await this.login(await loadUserByUsername(username, req, res), password)
        setCookies(res, authCookie, refreshCookie)
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
   * Verify the provided jwt cookie and set the user on the request to the parser user in the jwt
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
   * @param req The incoming request
   * @param res The outgoing response
   * @param fn The function to run and listen for {@link UnauthorizedError}
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

  static #buildConfig (options) {
    const config = {}
    config.login = buildLoginConfig(options.login)
    config.locking = buildLockingConfig(options.locking)
    config.tokens = {}
    for (const token of ['auth', 'refresh']) {
      config.tokens[token] = buildTokenConfig(token, options.tokens[token] || {}, options)
    }
    return config
  }
}

/**
 * Check whether the userRoles contains at least one of the requiredRoles
 * @param requiredRoles An array of the roles the user must have one of
 * @param userRoles An array of the roles the user is assigned
 */
export const hasAnyRole = (requiredRoles, userRoles) => {
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
 * @param requiredRoles An array of the roles the user must have one of
 * @param userRoles An array of the roles the user is assigned
 */
export const hasAllRoles = (requiredRoles, userRoles) => {
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
 * @param requiredRoles {string} The roles the user must have one of
 * @return {(function(*, *, *): void)|*} a new middleware function that reads the user's roles from req.user.roles and validates the user has any of required roles
 */
export const hasAnyRoleMiddleware = (...requiredRoles) => {
  return (req, res, next) => {
    if (hasAnyRole(requiredRoles, req.user.roles)) {
      return next()
    } else {
      return endRes(res, 403, 'Forbidden')
    }
  }
}

/**
 * Create a middleware to validate the current user has all the required roles
 * @param requiredRoles {string} The roles the user must have all of
 * @return {(function(*, *, *): void)|*} a new middleware function that reads the user's roles form req.user.roles and validates the user has any of the required roles
 */
export const hasAllRolesMiddleware = (...requiredRoles) => {
  return (req, res, next) => {
    if (hasAllRoles(requiredRoles, req.user.roles)) {
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
 * @property {object|string} [body] An object or message to use as the response body
 */
export class HttpError extends Error {
  constructor (statusCode, statusMessage, body) {
    super(body)
    this.statusCode = statusCode
    this.statusMessage = statusMessage
    this.body = body ?? ''
  }
}

/**
 * An HttpError with 401 statusCode and Unauthorized statusMessage
 * @property {object|string} [body] An object or message to use as the response body
 * @property {Error} [cause] The error that caused this error to be thrown, if any
 */
export class UnauthorizedError extends HttpError {
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
 * @param {string} cookies The cookies to add to the set-cookie header
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
 * Set cookies on the response. The cookies should be serialized strings.
 * If there are existing values for set-cookie, they will not be overridden.
 *
 * @param {AuthResponse} res The response object to set the cookies on
 * @param {string} cookieNames The names of the cookies to add to the set-cookie header
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
 * @param {LoginOptions} input
 * @returns {LoginOptions}
 */
function buildLoginConfig (input) {
  const out = {}
  out.hashPassword = valOrDefault(ensureFn(input, 'hashPassword', true), createSha512Hmac)
  out.userToJwtPayload = valOrDefault(ensureFn(input, 'userToJwtPayload', true), user => ( {
    sub: user.username,
    username: user.username,
    roles: user.roles || []
  } ))
  out.loadUserByUsername = ensureFn(input, 'loadUserByUsername', true)
  out.storeRefreshToken = ensureFn(input, 'storeRefreshToken', false)
  out.invalidateRefreshToken = ensureFn(input, 'invalidateRefreshToken', false)
  out.checkRefreshTokenValid = ensureFn(input, 'checkRefreshTokenValid', false)
  return out
}

/**
 * Validate the provided locking options and construct a config with defaults
 * @param {LockingOptions} input
 * @returns {LockingOptions}
 */
function buildLockingConfig (input) {
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

  const defaultTimeout = name === 'refresh' ? '1d' : '5m'
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
  if (!out.secret && ( !out.keys || typeof out.keys !== 'object' )) {
    throw new Error('You must specify either secret or keys for each token')
  }
  return out
}

function mergeConfig(...objects){
  const res = {}
  for(const obj of objects){
    Object.assign(res, obj || {})
  }
  return res
}

function handleHttpError (res, e, next) {
  if (e instanceof HttpError) {
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
 * @param type The type the property must be (compared to the result of typeof on the property value)
 * @param optional Whether the property is optional, throws an error if false
 * @return {*}
 */
function ensureType (obj, prop, type, optional = false) {
  if (!optional && !obj[prop]) {
    throw new Error(`${prop} must be defined`)
  }
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
  if (obj[prop] && typeof obj[prop] !== 'string' && !( obj[prop] instanceof Buffer )) {
    throw new Error(`${prop} must be of a string or a Buffer`)
  }
  return obj[prop]
}
const valOrDefault = (value, defaultValue) => typeof value === typeof defaultValue ? value : defaultValue
