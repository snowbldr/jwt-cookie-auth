# jwt-cookie-auth
Authentication and authorization using JWTs stored in cookies for maintaining stateless sessions

### Getting Started
To begin, create a JwtAuthorizer

```javascript
const authorizer = JwtCookieAuthorizer({
  jwtSecret: 'mySecret'
})
```

Create a function to load the user
```javascript
function loadUser(username, req, res) {
  return myDb.findByUsername(username)
}
```

The load user function must return an object
```javascript
const user = {
  //required fields
  username: 'String, the user\'s unique name, used as sub jwt field',
  passwordHash: 'String, the stored hash of the password',
  salt: 'String, a random salt to use in the password hash function',
  //optional fields
  roles: ['String[], a list of roles the user is assigned, added to jwt as roles field'],
  lockedAt: new Date(), // or null, required if enableLocking is true,
  failedLogins: 10 //Int, required if enableLocking is true
}
```

Add the login middleware to a route to be used for login
```javascript
app.get('/login', keyAuthorizer.basicAuthLoginMiddleware(loadUser), (req, res)=>{
  res.send(JSON.stringify(req.user))
})
```

Add the authorizer to secured route
```javascript
app.get('/secure/secrets', keyAuthorizer.authorizeMiddleware(), (req, res) => {
  res.send(req.user.username)
})
```

That's it, you're ready to authenticate users!

#### Examples
The "examples" directory provides examples of using this library with several common http frameworks.

#### Framework Support
This library supports the following frameworks:
- express (4 and 5)
- spliffy
- fastify
- node http

Express, spliffy, and fastify are supported via middleware, if your framework supports express style middleware,
it will likely work without any modification.

The method used in the node implementation will work with any framework, but is a tad more verbose.

#### JwtCookieAuthorizer Options Reference
- **jwtSecret**: String/Buffer, A secret value used for creating and validating JSON Web Tokens, cannot be set if jwtKeys passed
- **jwtKeys**: An object with a private and public key, cannot be set if jwtSecret is passed
  - **private**: String/Buffer, The PEM encoded private key
  - **public**: String/Buffer, The PEM encoded public key
- **jwtSignOptions**: Options object passed verbatim to jwt.sign. See https://www.npmjs.com/package/jsonwebtoken
- **jwtVerifyOptions**: Options object passed verbatim to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken
- **passwordHashFn**: Function, a function to hash the password. Uses sha512 hash from crypto package by default.
- **userToJwtPayload**: Function, An optional function to map the user to the jwt payload when a token is created.
  The username is used as sub by default, and roles are passed if any are provided.
- **jwtCookieName**: String, the cookie name to store the token into. Defaults to jwt-auth
- **jwtCookieConfig**: Object, configuration options to pass to the setCookie call for the jwt-auth cookie
- **enableLocking**: Boolean, whether to enable locking out the user for some time after some failed login attempts. Defaults to false.
- **maxFailedLogins:** Int, the maximum number of login attempts to allow before locking the user. Defaults to 10.
- **lockSeconds**: Int, the number of seconds to lock the user after reaching the max failed attempts. Defaults to 10 minutes.
- **setLockStatus**: Function, Update the user when it's lock status is changed. Required if enableLocking is true.
  This function should persist the changes to the user.

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