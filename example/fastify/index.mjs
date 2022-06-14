import Fastify from 'fastify'
import fastifyExpress from 'fastify-express'
import {
  hasAllRolesMiddleware,
  hasAnyRoleMiddleware
} from '../../index.js'
import { keyAuthorizer, loadUserByUsername, validRefreshTokens } from '../authorizer.mjs'

const app = Fastify({ logger: true })

const authMiddleware = keyAuthorizer.authorizeMiddleware()

async function start () {
  await app.register(fastifyExpress)
  app.get('/health', (req, res) => res.send('OK'))

  app.get('/login', (req, res) => {
    res.send(JSON.stringify(req.raw.user))
  })
  app.use('/login', keyAuthorizer.basicAuthLoginMiddleware())

  app.get('/logout', (req, res) => {
    res.send('OK')
  })
  app.use('/logout', keyAuthorizer.logoutMiddleware())

  app.get('/refresh', (req, res) => {
    res.send(JSON.stringify(req.raw.user))
  })
  app.use('/refresh', keyAuthorizer.refreshAuthMiddleware(true))

  app.get('/refreshTokens', (req, res) => {
    res.send(JSON.stringify(validRefreshTokens))
  })

  app.use('/secure/*', authMiddleware)
  app.get('/secure/secrets', (req, res) => {
    res.send(req.raw.user.username)
  })

  app.get('/secure/anyRole', (req, res) => {
    res.send(req.raw.user.username)
  })
  app.use('/secure/anyRole', hasAnyRoleMiddleware('sauce boss', 'taco master', 'user'))

  app.get('/secure/allRoles', (req, res) => {
    res.send(req.raw.user.username)
  })
  app.use('/secure/allRoles', hasAllRolesMiddleware('user', 'admin', 'donut eater'))

  app.get('/user', (req, res) => {
    res.send(JSON.stringify(loadUserByUsername(req.query.username)))
  })

  app.get('/resetUser', (req, res) => {
    const user = loadUserByUsername(req.query.username)
    user.failedLogins = 0
    user.lockedAt = null
    res.end()
  })

  await app.listen(33333)
  console.log('Server initialized')
}

await start()
