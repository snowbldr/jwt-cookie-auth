import Fastify from 'fastify'
import fastifyExpress from 'fastify-express'
import {
  hasAllRolesMiddleware,
  hasAnyRoleMiddleware
} from '../../index.mjs'
import { keyAuthorizer, loadUser } from '../authorizer.mjs'

const fastify = Fastify({ logger: true })

const authMiddleware = keyAuthorizer.authorizeMiddleware()

async function start () {
  await fastify.register(fastifyExpress)
  fastify.get('/health', (req, res) => res.send('OK'))

  fastify.get('/login', (req, res) => {
    res.send(JSON.stringify(req.raw.user))
  })

  fastify.use('/login', keyAuthorizer.basicAuthLoginMiddleware(loadUser))

  fastify.use('/secure/*', authMiddleware)

  fastify.get('/secure/secrets', (req, res) => {
    res.send(req.raw.user.username)
  })

  fastify.get('/secure/anyRole', (req, res) => {
    res.send(req.raw.user.username)
  })
  fastify.use('/secure/anyRole', hasAnyRoleMiddleware('sauce boss', 'taco master', 'user'))

  fastify.get('/secure/allRoles', (req, res) => {
    res.send(req.raw.user.username)
  })
  fastify.use('/secure/allRoles', hasAllRolesMiddleware('user', 'admin', 'donut eater'))

  fastify.get('/user', (req, res) => {
    res.send(JSON.stringify(loadUser(req.query.username)))
  })

  fastify.get('/resetUser', (req, res) => {
    const user = loadUser(req.query.username)
    user.failedLogins = 0
    user.lockedAt = null
    res.end()
  })

  await fastify.listen(33333)
  console.log('Server initialized')
}

await start()
