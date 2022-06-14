[Documentation](../README.md) / [Exports](../modules.md) / AuthorizerOptions

# Interface: AuthorizerOptions<\>

## Table of contents

### Properties

- [cookieConfig](AuthorizerOptions.md#cookieconfig)
- [keys](AuthorizerOptions.md#keys)
- [locking](AuthorizerOptions.md#locking)
- [login](AuthorizerOptions.md#login)
- [refreshEnabled](AuthorizerOptions.md#refreshenabled)
- [secret](AuthorizerOptions.md#secret)
- [signOptions](AuthorizerOptions.md#signoptions)
- [tokens](AuthorizerOptions.md#tokens)
- [verifyOptions](AuthorizerOptions.md#verifyoptions)

## Properties

### cookieConfig

• **cookieConfig**: `any`

The default configuration options to pass cookie.serialize See https://www.npmjs.com/package/cookie

#### Defined in

[index.js:333](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L333)

___

### keys

• **keys**: [`JwtKeys`](JwtKeys.md)

The default keys used to sign and verify JWTs, cannot be set if secret is provided

#### Defined in

[index.js:327](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L327)

___

### locking

• **locking**: [`LockingOptions`](LockingOptions.md)

Options related to locking users, locking is disabled if this is not set

#### Defined in

[index.js:318](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L318)

___

### login

• **login**: [`LoginOperations`](LoginOperations.md)

Operations for login and refresh

#### Defined in

[index.js:317](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L317)

___

### refreshEnabled

• **refreshEnabled**: `boolean`

Whether refresh tokens are enabled.
This is true by default and the corresponding refresh methods must be provided on the LoginOperations.

If this is disabled, it will disable the ability to log out users, and will prevent refresh tokens from being created.

It is not recommended to disable refresh for anything important, but is fine for toy apps and non-critical applications

#### Defined in

[index.js:320](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L320)

___

### secret

• **secret**: `string` \| `Buffer`

The default secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided

#### Defined in

[index.js:326](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L326)

___

### signOptions

• **signOptions**: `any`

The default options passed to sign when creating a token.
Recommended to pass issuer and expiresIn at minimum.
See https://www.npmjs.com/package/jsonwebtoken
example: {issuer: 'my-app', expiresIn: '3m'}

#### Defined in

[index.js:328](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L328)

___

### tokens

• **tokens**: [`Tokens`](Tokens.md)

Token configurations

#### Defined in

[index.js:319](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L319)

___

### verifyOptions

• **verifyOptions**: `any`

The default options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken

#### Defined in

[index.js:332](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L332)
