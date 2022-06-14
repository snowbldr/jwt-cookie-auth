import http from 'http'
import { hasAllRoles, hasAnyRole, HttpStatusError } from '../../index.js'
import { loadUserByUsername, secretAuthorizer, validRefreshTokens } from '../authorizer.mjs'

const authorized = (fn) => async (req, res) => {
  await secretAuthorizer.verifyAuth(req, res)
  return fn(req, res)
}

const roleCheck = (roleFn, roles, fn) => {
  return (req, res) => {
    if (roleFn(req.user.roles, ...roles)) {
      return fn(req, res)
    } else {
      res.statusCode = 403
    }
  }
}

const routes = {
  '/health': async (req, res) => res.write('OK'),
  '/login': async (req, res) => {
    await secretAuthorizer.basicAuthLogin(req, res)
    res.write(JSON.stringify(req.user))
  },
  '/logout': async (req, res) => {
    await secretAuthorizer.logout(req, res)
    res.write('OK')
  },
  '/refresh': async (req, res) => {
    await secretAuthorizer.refreshAuthCookie(req, res, true)
    res.write(JSON.stringify(req.user))
  },
  '/refreshTokens': (req, res) => {
    res.write(JSON.stringify(validRefreshTokens))
  },
  '/secure/secrets': authorized((req, res) => res.write(req.user.username)),
  '/secure/anyRole': authorized(
    roleCheck(hasAnyRole, ['sauce boss', 'taco master', 'user'],
      (req, res) => {
        res.write(req.user.username)
      })
  ),
  '/secure/allRoles': authorized(
    roleCheck(hasAllRoles, ['user', 'admin', 'donut eater'],
      (req, res) => {
        res.write(req.user.username)
      })
  ),
  '/user': (req, res) => {
    res.write(JSON.stringify(loadUserByUsername(req.query.username)))
  },
  '/resetUser': (req, res) => {
    const user = loadUserByUsername(req.query.username)
    user.failedLogins = 0
    user.lockedAt = null
  }
}

async function handle (req, res) {
  const [path, query] = req.url.split('?')
  req.query = query?.split('&').map(q => q.split('=')).reduce((query, q) => {
    query[q[0]] = q[1]
    return query
  }, {})
  if (path in routes) {
    await routes[path](req, res)
  } else {
    res.statusCode = 404
    res.write('Not Found')
  }
}

http.createServer((req, res) => {
  handle(req, res).then(res.end).catch(e => {
    if (e instanceof HttpStatusError) {
      res.statusCode = e.statusCode
      res.statusMessage = e.statusMessage
      res.setHeader('content-type', 'application/json')
      res.write(JSON.stringify(e.body))
    } else {
      e.statusCode = 500
      res.statusMessage = 'Internal Error'
    }
    res.end()
  })
}).listen(33334)
console.log('Server initialized')
