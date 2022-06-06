import express from 'express'
import {
  hasAnyRoleMiddleware,
  hasAllRolesMiddleware
} from 'jwt-cookie-auth'
import { loadUserByUsername, secretAuthorizer, validRefreshTokens } from '../authorizer.mjs'

const app = express()

const authMiddleware = secretAuthorizer.authorizeMiddleware()

app.get('/health', (req, res) => res.send('OK'))

app.get('/login', secretAuthorizer.basicAuthLoginMiddleware(), (req, res) => {
  res.send(JSON.stringify(req.user))
})

app.get('/logout', secretAuthorizer.logoutMiddleware(), (req, res) => {
  res.send('OK')
})

app.get('/refresh', secretAuthorizer.refreshAuthMiddleware(true), (req, res) => {
  res.send(JSON.stringify(req.user))
})

app.get('/refreshTokens', (req, res) => {
  res.send(JSON.stringify(validRefreshTokens))
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
  res.send(JSON.stringify(loadUserByUsername(req.query.username)))
})

app.get('/resetUser', (req, res) => {
  const user = loadUserByUsername(req.query.username)
  user.failedLogins = 0
  user.lockedAt = null
  res.end()
})
app.listen(33332)
console.log('Server initialized')
