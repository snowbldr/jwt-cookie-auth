# jwt-cookie-auth
Authentication and authorization using JWTs stored in cookies for maintaining sessions

### Getting Started
To begin, create a JwtAuthorizer with the necessary functions.

```javascript
const authorizer = JwtCookieAuthorizer({
  secret: 'mySecret',
  login: {
    loadUserByUsername: username => myDb.findByUsername(username),
    storeRefreshToken: (user, token) => myDb.saveRefreshToken({token, user}),
    checkRefreshTokenValid: (user, token) => myDb.refreshTokenExists(user.username, token),
    invalidateRefreshToken: (user, token) => myDb.deleteRefreshToken(user.username, token)
  }
})
```
Token refreshing is enabled by default, as it provides the most secure mode by enabling global logout.
Having this enabled means authentication is not completely stateless, and that each time the token is refreshed you
will need to check the validity of the refresh token against your storage. While being stateful, this is still
an improvement over storing sessions in a central store as it doesn't need to be checked on every request, but only
when refreshing the auth token.

To disable the use of refresh tokens and have regular stateless jwts, set refreshEnabled to false. You do not need
to pass the refresh related functions if refresh tokens are disabled. 

The complete JwtCookieAuthorizer options reference is here: [AuthorizerOptions](./docs/interfaces/AuthorizerOptions.md)

The load user function must return a [PersistedUser](./docs/classes/PersistedUser.md) 
```javascript
const user = {
  //required fields
  username: 'rickJames',
  passwordHash: '!mR!cKJ@m35817c#',
  salt: '1234saltytlas4321',
  //optional fields
  roles: ['not-allowed-on-the-couch']
}
```

Add the login middleware to a route to be used for login
```javascript
app.get('/login', keyAuthorizer.basicAuthLoginMiddleware(), (req, res)=>{
  res.send(`${req.user.username}, you're logged in!`)
})
```

Add the authorizer to secured route
```javascript
app.get('/secure/secrets', keyAuthorizer.authorizeMiddleware(), (req, res) => {
  res.send(`Your name is: ${req.user.username}`)
})
```

Add a logout end point to log users out
```javascript
app.get('/logout', keyAuthorizer.authorizeMiddleware(), (req, res) => {
  res.send('logged out')
})
```

That's it, you're ready to authenticate users!

### Locking
User lockout is supported by setting the `locking` property when creating the authorizer

At minimum, you must provide a `setLockStatus` function that will persist the lock status of the user
```javascript
const authorizer = JwtCookieAuthorizer({
  ...,
  locking: {
    setLockStatus(userLockEvent){
      db.updateUserLockStatus(userLockEvent)
    }
  }
})
```

See [LockingOptions](./docs/interfaces/LockingOptions.md) for all configuration options

### Reference Docs
See [Js Doc Reference](./docs/modules.md)

#### Examples
The "examples" directory provides examples of using this library with several common http frameworks.

See the minimal example for the easiest way to get started.

#### Framework Support
This library supports the following frameworks:
- express (4 and 5)
- spliffy
- fastify
- node http

Express, spliffy, and fastify are supported via middleware, if your framework supports express style middleware,
it will likely work without any modification.

The method used in the node implementation will work with any framework, but is a tad more verbose.

## Why use a cookie
Using a cookie to store a JWT means you're vulnerable to CSRF attacks, and you _will_ need to set up CSRF protection in your chosen framework.

If that's the case, why use a cookie for auth?

This may seem risky, however the alternative is to make your JWTs available to Javascript, so it can be sent by the client manually,
and that opens you up to very simple XSS attacks which can be far more devastating and can be much more difficult to circumvent.

Not using a cookie also means your front end client code needs to be a bit more complex, when it doesn't need to be.

You can read more about the tradeoffs here: https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage#where-to-store-your-jwts
and here: https://supertokens.com/blog/cookies-vs-localstorage-for-sessions-everything-you-need-to-know

Owasp is also a great resource on the topic of localstorage vs cookies, https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage

On that page, OWASP explicitly states:
>Do not store session identifiers in local storage as the data is always accessible by JavaScript. Cookies can mitigate this risk using the httpOnly flag.

This library enforces the httpOnly flag is set to true on the jwt cookie.

### CSRF Prevention
You _SHOULD_ set up CSRF protection, as using cookies for authentication exposes you to potential CSRF attacks.

For express, and frameworks that support express middleware, you can use the csurf (https://github.com/expressjs/csurf) middleware.

In case you cannot use that with your framework, and your framework does not provide csrf mitigation otherwise, OWASP has great information on preventing CSRF attacks here: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
