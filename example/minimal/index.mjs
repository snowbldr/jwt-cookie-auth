import express from 'express'
import {
  hasAnyRoleMiddleware,
  hasAllRolesMiddleware,
  JwtCookieAuthorizer,
  createSha512Hmac
} from 'jwt-cookie-auth'

// mock user store, would normally be a database
const users = {
  taco: {
    username: 'taco',
    salt: 'salty',
    roles: ['taco master', 'admin'],
    passwordHash: createSha512Hmac('password123', 'salty')
  }
}

const authorizer = new JwtCookieAuthorizer({
  refreshEnabled: false,
  secret: 'supa-secret',
  login: {
    loadUserByUsername: username => users[username]
  }
})

const app = express()

const authMiddleware = authorizer.authorizeMiddleware()

app.get('/health', (req, res) => res.send('OK'))

app.get('/login', authorizer.basicAuthLoginMiddleware(), (req, res) => {
  res.send(JSON.stringify(req.user))
})

app.get('/logout', authorizer.logoutMiddleware(), (req, res) => {
  res.send('OK')
})

app.get('/secret', authMiddleware, (req, res) => {
  res.send(`Secret: your name is ${req.user.username}`)
})

app.get('/anyRole', authMiddleware, hasAnyRoleMiddleware('sauce boss', 'taco master', 'user'), (req, res) => {
  res.send(`You have these roles: ${JSON.stringify(req.user.roles)}`)
})

app.get('/allRoles', authMiddleware, hasAllRolesMiddleware('user', 'admin', 'donut eater'), (req, res) => {
  res.send(`You have these roles: ${JSON.stringify(req.user.roles)}`)
})

app.listen(8881)
console.log('Server initialized, listening on port 8881')
