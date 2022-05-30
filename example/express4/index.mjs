import express from 'express'
import {
  hasAnyRoleMiddleware,
  hasAllRolesMiddleware
} from 'jwt-cookie-auth'
import { keyAuthorizer, loadUser } from '../authorizer.mjs'

const app = express()

const authMiddleware = keyAuthorizer.authorizeMiddleware()

app.get('/health', (req, res) => res.send('OK'))

app.get('/login', keyAuthorizer.basicAuthLoginMiddleware(loadUser), (req, res) => {
  res.send(JSON.stringify(req.user))
})

app.get('/secure/secrets', authMiddleware, (req, res) => {
  res.send(req.user.username)
})

app.get('/secure/anyRole', authMiddleware, hasAnyRoleMiddleware('sauce boss', 'taco master', 'user'), (req, res) => {
  res.send(req.user.username)
})

app.get('/secure/allRoles', authMiddleware, hasAllRolesMiddleware('user', 'admin', 'donut eater'), (req, res) => {
  res.send(req.user.username)
})

app.get('/user', (req, res) => {
  res.send(JSON.stringify(loadUser(req.query.username)))
})

app.get('/resetUser', (req, res) => {
  const user = loadUser(req.query.username)
  user.failedLogins = 0
  user.lockedAt = null
  res.end()
})
app.listen(33331)
console.log('Server initialized')
