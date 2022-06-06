import { createSha512Hmac, JwtCookieAuthorizer } from '../index.mjs'
import { privateKey, publicKey } from './testKeys.mjs'

export const loadUserByUsername = (username) => users[username]

/**
 *
 * @return {AuthorizerOptions}
 */
const authorizerConfig = () => ({
  tokens: {
    auth: {
      signOptions: {
        expiresIn: '3s'
      }
    },
    refresh: {
      signOptions: {
        expiresIn: '6s'
      }
    }
  },
  signOptions: {
    issuer: 'jwt-authorizer',
    audience: 'users',
    keyid: '1234'
  },
  verifyOptions: {
    audience: 'users',
    issuer: 'jwt-authorizer'
  },
  cookieConfig: {
    maxAge: 10,
    secure: false,
    path: '/secure'
  },
  login: {
    loadUserByUsername,
    storeRefreshToken: (user, token) => { validRefreshTokens[token] = user.username },
    checkRefreshTokenValid: (user, token) => token in validRefreshTokens,
    invalidateRefreshToken: (user, token) => delete validRefreshTokens[token]
  },
  locking: {
    setLockStatus: ({ username, lockedAt, failedLogins }) => {
      const user = users[username]
      user.lockedAt = lockedAt
      user.failedLogins = failedLogins
    },
    lockSeconds: 3,
    maxFailedLogins: 2
  }
})

export const keyAuthorizer = new JwtCookieAuthorizer({
  ...authorizerConfig(),
  keys: {
    private: privateKey,
    public: publicKey
  }
})

export const secretAuthorizer = new JwtCookieAuthorizer({
  ...authorizerConfig(),
  secret: 'secret'
})

export const users = {
  taco: {
    username: 'taco',
    salt: 'salty',
    roles: ['taco master', 'admin'],
    passwordHash: createSha512Hmac('password123', 'salty'),
    lockedAt: null,
    failedLogins: 0
  },
  donut: {
    username: 'donut',
    salt: 'sweet',
    roles: ['user', 'admin', 'donut eater'],
    passwordHash: createSha512Hmac('password321', 'sweet'),
    lockedAt: null,
    failedLogins: 0
  },
  lockme: {
    username: 'lockme',
    salt: 'plz',
    roles: ['gun get locked'],
    passwordHash: createSha512Hmac('password333', 'plz'),
    lockedAt: null,
    failedLogins: 0
  },
  rando: {
    username: 'rando',
    salt: 'israndom',
    roles: ['access to nothing'],
    passwordHash: createSha512Hmac('password313', 'israndom'),
    lockedAt: null,
    failedLogins: 0
  }
}
export const validRefreshTokens = {}
