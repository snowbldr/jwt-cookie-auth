import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import cookie from 'cookie'
import { promisify } from 'util'

const signJwt = promisify(jwt.sign)
const verifyJwt = promisify(jwt.verify)

/**
 * Create a hmac sha512 hash of the given value and salt
 * @param value {string} The value to hash
 * @param salt {string} A salt to use to create the hmac
 * @return {string} A base64 hash of the value
 */
export function createSha512Hmac (value, salt) {
  const hash = crypto.createHmac('sha512', String(salt))
  hash.update(value)
  return hash.digest('base64')
}

/**
 * An Error with an associated http statusCode and statusMessage
 */
export class HttpError extends Error {
  constructor (statusCode, statusMessage, error) {
    super(error)
    this.statusCode = statusCode
    this.statusMessage = statusMessage
    if (error) this.body = { error }
  }
}

/**
 * An HttpError with 401 statusCode and Unauthorized statusMessage
 */
export class UnauthorizedError extends HttpError {
  constructor (error, cause) {
    super(401, 'Unauthorized', error)
    if (cause) this.stack += `\n${cause.stack}`
  }
}

/**
 * Set cookies on the response. The cookies should be serialized strings.
 * If there are existing values for set-cookie, they will not be overridden.
 *
 * @param res The response object to set the cookies on
 * @param cookies The cookies to add to the set-cookie header
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
 * An object that handles creating and authenticated jwts
 *
 * @param jwtSecret A secret value used for creating and validating JSON Web Tokens, cannot be set if jwtKeys passed
 * @param jwtKeys An object with a private and public key, cannot be set if jwtSecret is passed
 *          example: {
 *              private: '-----BEGIN PRIVATE KEY-----...'
 *              public: '-----BEGIN PUBLIC KEY-----...'
 *          }
 * @param jwtSignOptions Options passed to jwt.sign. Recommended to pass issuer and expiresIn at minimum. See https://www.npmjs.com/package/jsonwebtoken
 *        example: {issuer: 'my-app', expiresIn: '10m'}
 * @param jwtVerifyOptions Options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
 * @param passwordHashFn Function, a function to hash the password. Uses sha512 hash from crypto package by default.
 * @param maxFailedLogins Int, the maximum number of login attempts to allow before locking the user. Defaults to 10.
 * @param lockSeconds Int, the number of seconds to lock the user after reaching the max failed attempts. Defaults to 10 minutes.
 * @param userToJwtPayload Function, An optional function to map the user to the jwt payload when a token is created.
 *          The username is used as sub by default, and roles are passed if any are provided.
 *          jwtPayload = {
 *              sub: user.username,
 *              roles: user.roles || []
 *          }
 *
 * @param jwtCookieName String, the cookie name to store the token into. Defaults to jwt-session
 * @param jwtCookieConfig Object, configuration options to pass to the setCookie call for the jwt-session cookie
 * @param enableLocking Boolean, whether to enable locking out the user for some time after some failed login attempts. Defaults to false.
 *
 * @param setLockStatus Function, Update the user when it's lock status is changed. Required if enableLocking is true.
 * This function should persist the changes to the user.
 *
 * Receives an object with shape:
 *      { username: String,
 *        failedLogins: Int,
 *        lockedAt: Date,
 *        action: String
 *      }
 *
 * action can be one of: 'failedAttempt', 'locked', or 'unlocked'
 */
export class JwtCookieAuthorizer {
  #config

  // destructuring used to help code completion and jsdoc param resolution
  constructor ({
    jwtSecret,
    jwtKeys,
    jwtSignOptions,
    jwtVerifyOptions,
    passwordHashFn,
    maxFailedLogins,
    lockSeconds,
    userToJwtPayload,
    jwtCookieName,
    jwtCookieConfig,
    enableLocking,
    setLockStatus
  }) {
    this.#config = JwtCookieAuthorizer.#buildConfig(arguments[0])
  }

  /**
   * Verify the provided jwt cookie
   */
  async verify (req) {
    const jwtToken = this.getJwtCookie(req)
    if (jwtToken) {
      try {
        req.user = await verifyJwt(jwtToken, this.#config.jwtVerifySecret, this.#config.jwtVerifyOptions)
      } catch (e) {
        throw new UnauthorizedError('Invalid Jwt', e)
      }
    } else {
      throw new UnauthorizedError('Jwt cookie not provided')
    }
  }

  /**
   * Create a jwt cookie
   * @param jwtToken The jwt token to create a cookie for
   * @returns {String} The serialized jwt cookie
   */
  createJwtCookie (jwtToken) {
    return cookie.serialize(this.#config.jwtCookieName, jwtToken, {
      maxAge: 60 * 60, // 1 hour
      secure: true,
      ...valOrDefault(this.#config.jwtCookieConfig, {}),
      // Don't allow authorization cookies to be read by js
      httpOnly: true
    })
  }

  getJwtCookie (req) {
    if (typeof req.cookies === 'object') {
      return req.cookies[this.#config.jwtCookieName]
    } else if (req.headers?.cookie) {
      const cookies = cookie.parse(req.headers.cookie)
      return cookies[this.#config.jwtCookieName]
    }
  }

  /**
   * Attempt to login the provided user and create a new jwt token
   * @param user The user to log in.
   *      -- Required Fields
   *      - username: String, the user's unique name, used as sub jwt field
   *      - passwordHash: String, the stored hash of the password
   *      - salt: String, a random salt to use in the password hash function
   *      -- Optional Fields
   *      - roles: String[], a list of roles the user is assigned, added to jwt as roles field
   *      - lockedAt: Date or null, required if enableLocking is true
   *      - failedLogins: Int, required if enableLocking is true
   * @param password The password provided on the login attempt
   * @return {Promise<*>} An object containing the new jwt token, and the jwt user (the passed in user, mapped to jwt payload)
   *    {
   *      jwtToken: 'new.jwt.token',
   *      jwtUser: {
   *        sub: user.username,
   *        username: user.username,
   *        roles: user.roles
   *      }
   *    }
   */
  async login (user, password) {
    if (!user) {
      throw new UnauthorizedError('Login Failed')
    }

    if (this.#config.enableLocking && user.lockedAt && new Date().getTime() < user.lockedAt.getTime() + (this.#config.lockSeconds * 1000)) {
      throw new UnauthorizedError('Your user is locked, try again later.')
    }
    if (!user.passwordHash) {
      throw new UnauthorizedError('Login Failed')
    }

    const incoming = this.#config.passwordHashFn(password, user.salt)

    if (incoming !== user.passwordHash) {
      if (this.#config.enableLocking) {
        if (typeof user.failedLogins !== 'number') {
          user.failedLogins = 0
        }
        if (user.failedLogins >= this.#config.maxFailedLogins) {
          await this.#config.setLockStatus({
            username: user.username,
            failedLogins: user.failedLogins + 1,
            lockedAt: new Date(),
            action: 'locked'
          })
          throw new UnauthorizedError('Too many failed attempts, user locked.')
        }
        await this.#config.setLockStatus({
          username: user.username,
          failedLogins: user.failedLogins + 1,
          lockedAt: null,
          action: 'failedAttempt'
        })
      }
      throw new UnauthorizedError('Login Failed')
    }

    if (user.lockedAt || user.failedLogins > 0) {
      await this.#config.setLockStatus({ username: user.username, failedLogins: 0, lockedAt: null, action: 'unlocked' })
    }

    const jwtUser = this.#config.userToJwtPayload(user)
    const jwtToken = await this.createJwtToken(jwtUser)

    return {
      jwtToken,
      jwtCookie: this.createJwtCookie(jwtToken),
      jwtUser
    }
  }

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

  async createJwtToken (jwtInfo) {
    return signJwt(jwtInfo, this.#getSignSecret(), this.#config.jwtSignOptions)
  }

  /**
   * @param req The current request with a headers object containing the request headers
   * @param res The current response to set the cookies on
   * @param loadUserByUsername A function to load the user data by username.
   *          Can be async, receives the username, request, and response as params.
   *      Must return a user object with the fields:
   *      -- Required Fields
   *      - username: String, the user's unique name, used as sub jwt field
   *      - passwordHash: String, the stored hash of the password
   *      - salt: String, a random salt to use in the password hash function
   *      -- Optional Fields
   *      - roles: String[], a list of roles the user is assigned, added to jwt as roles field
   *      - lockedAt: Date or null, required if enableLocking is true
   *      - failedLogins: Int, required if enableLocking is true
   * @return {Promise<void>}
   */
  async basicAuthLogin (req, res, loadUserByUsername) {
    ensureFn(loadUserByUsername, 'loadUserByUsername must be a function')
    const authHeader = req.headers.authorization
    if (authHeader) {
      const { username, password } = this.parseBasicAuthHeader(authHeader)
      const { jwtToken, jwtCookie, jwtUser } = await this.login(await loadUserByUsername(username, req, res), password)
      setCookies(res, jwtCookie)
      req.user = jwtUser
      req.jwtToken = jwtToken
    } else {
      throw new UnauthorizedError('Authorization not provided')
    }
  }

  /**
   * @param loadUserByUsername A function to load the user data by username.
   *          Can be async, receives the username, request, and response as params.
   *      Must return a user object with the fields:
   *      -- Required Fields
   *      - username: String, the user's unique name, used as sub jwt field
   *      - passwordHash: String, the stored hash of the password
   *      - salt: String, a random salt to use in the password hash function
   *      -- Optional Fields
   *      - roles: String[], a list of roles the user is assigned, added to jwt as roles field
   *      - lockedAt: Date or null, required if enableLocking is true
   *      - failedLogins: Int, required if enableLocking is true
   * @return {(function(*, *, *): void)|*} A middleware that will authorize the request using the provided authorizer
   */
  basicAuthLoginMiddleware (loadUserByUsername) {
    ensureFn(loadUserByUsername, 'loadUserByUsername must be a function')
    return (req, res, next) =>
      this.basicAuthLogin(req, res, loadUserByUsername)
        .then(next)
        .catch(e => next(e))
  }

  /**
   * Create a new middleware function that will exchange basic auth for a jwt token or will validate an existing jwt
   *
   * @return {(function(*, *, *): void)|*} A middleware that will authorize the request using this authorizer
   */
  authorizeMiddleware () {
    return (req, res, next) => {
      this.verify(req)
        .then(next)
        .catch(e => {
          if (e instanceof HttpError) {
            res.statusCode = e.statusCode
            res.statusMessage = e.statusMessage
            next(e)
          } else {
            next(e)
          }
        })
    }
  }

  #getSignSecret () {
    if (!this.#config.jwtSignSecret) {
      throw new Error('No jwt secret configured, cannot create tokens')
    }
    return this.#config.jwtSignSecret
  }

  static #buildConfig (options) {
    const config = {}
    if (!options.jwtSecret && !options.jwtKeys) {
      throw new Error('you must provide either jwtSecret or jwtKeys')
    }

    if (options.jwtSecret && typeof options.jwtSecret !== 'string' && !(options.jwtSecret instanceof Buffer)) {
      throw new Error('jwtSecret must be a string or buffer')
    }
    if (options.jwtKeys) {
      if (typeof options.jwtKeys !== 'object') {
        throw new Error('jwtKeys must be an object')
      }
      if (!options.jwtKeys.public || (typeof options.jwtKeys.public !== 'string' && !(options.jwtKeys.public instanceof Buffer))) {
        throw new Error('you must provide jwtKeys.public, and it must be either a string or buffer.')
      }
      if (!options.jwtKeys.private) {
        console.info('jwtKeys.private not provided, will not be able to create tokens')
      } else if (typeof options.jwtKeys.private !== 'string' && !(options.jwtKeys.private instanceof Buffer)) {
        throw new Error('jwtKeys.private must be either a string or buffer.')
      }
    }

    if (options.jwtKeys && options.jwtSecret) {
      throw new Error('you cannot provide both jwtKeys and jwtSecret')
    }

    config.jwtSignSecret = options.jwtKeys?.private || options.jwtSecret
    config.jwtVerifySecret = options.jwtKeys?.public || options.jwtSecret
    const algorithm = options.jwtSecret ? 'HS512' : 'RS512'
    config.jwtSignOptions = options.jwtSignOptions || {}
    if (!config.jwtSignOptions.algorithm) {
      config.jwtSignOptions.algorithm = algorithm
    }
    config.jwtVerifyOptions = options.jwtVerifyOptions || {}
    if (!config.jwtVerifyOptions.algorithms) {
      config.jwtVerifyOptions.algorithms = [algorithm]
    }
    config.enableLocking = valOrDefault(options.enableLocking, false)
    if (config.enableLocking) {
      config.setLockStatus = ensureFn(options.setLockStatus, 'setLockStatus must be a function')
    }
    config.passwordHashFn = valOrDefault(options.passwordHashFn, createSha512Hmac)
    config.lockSeconds = valOrDefault(options.lockSeconds, 600)
    config.maxFailedLogins = valOrDefault(options.maxFailedLogins, 10)
    config.jwtCookieName = valOrDefault(options.jwtCookieName, 'jwt-session')
    config.jwtCookieConfig = valOrDefault(options.jwtCookieConfig, {})
    if (config.jwtCookieConfig.httpOnly === false) {
      throw new Error('Jwt cookies must have httpOnly set to true')
    }
    config.userToJwtPayload = valOrDefault(options.userToJwtPayload, user => ({
      sub: user.username,
      username: user.username,
      roles: user.roles || []
    }))
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
 * Check whether the userRoles contains all of the requiredRoles
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
 * Create a middleware to validate the current user has all of the required roles
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

function endRes (res, statusCode, message) {
  res.statusCode = statusCode
  res.statusMessage = message
  return res.end()
}

const ensureFn = (fn, error) => {
  if (typeof fn !== 'function') {
    throw new Error(error)
  }
  return fn
}

const valOrDefault = (configValue, defaultValue) => typeof configValue === typeof defaultValue ? configValue : defaultValue
