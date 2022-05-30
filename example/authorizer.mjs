import { createSha512Hmac, JwtCookieAuthorizer } from '../index.mjs'
import { privateKey, publicKey } from './testKeys.mjs'

const authorizerConfig = () => ({
  jwtSignOptions: {
    expiresIn: '3s',
    issuer: 'jwt-authorizer',
    audience: 'users',
    keyid: '1234'
  },
  jwtVerifyOptions: {
    audience: 'users',
    issuer: 'jwt-authorizer'
  },
  enableLocking: true,
  setLockStatus: ({ username, lockedAt, failedLogins }) => {
    const user = users[username]
    user.lockedAt = lockedAt
    user.failedLogins = failedLogins
  },
  jwtCookieConfig: {
    maxAge: 60,
    secure: false,
    path: '/secure'
  },
  lockSeconds: 3,
  maxFailedLogins: 2
})

export const keyAuthorizer = new JwtCookieAuthorizer({
  ...authorizerConfig(),
  jwtKeys: {
    private: privateKey,
    public: publicKey
  }
})

export const secretAuthorizer = new JwtCookieAuthorizer({
  ...authorizerConfig(),
  jwtSecret: 'secret'
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

export const loadUser = (username) => users[username]
