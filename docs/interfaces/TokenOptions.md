[Documentation](../README.md) / [Exports](../modules.md) / TokenOptions

# Interface: TokenOptions<\>

## Table of contents

### Properties

- [cookieConfig](TokenOptions.md#cookieconfig)
- [cookieName](TokenOptions.md#cookiename)
- [keys](TokenOptions.md#keys)
- [secret](TokenOptions.md#secret)
- [signOptions](TokenOptions.md#signoptions)
- [verifyOptions](TokenOptions.md#verifyoptions)

## Properties

### cookieConfig

• **cookieConfig**: `any`

Configuration options to pass cookie.serialize See https://www.npmjs.com/package/cookie

#### Defined in

[index.js:201](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L201)

___

### cookieName

• **cookieName**: `string`

The cookie name to store the token into, defaults to jwt-${name} where name is either auth or refresh

#### Defined in

[index.js:200](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L200)

___

### keys

• **keys**: [`JwtKeys`](JwtKeys.md)

Keys used to sign and verify JWTs, cannot be set if secret is provided

#### Defined in

[index.js:194](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L194)

___

### secret

• **secret**: `string` \| `Buffer`

The secret value used for creating and validating JSON Web Tokens, cannot be set if keys are provided

#### Defined in

[index.js:193](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L193)

___

### signOptions

• **signOptions**: `any`

Options passed to sign when creating a token.
Recommended to pass issuer and expiresIn at minimum.
See https://www.npmjs.com/package/jsonwebtoken
example: {issuer: 'my-app', expiresIn: '3m'}

#### Defined in

[index.js:195](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L195)

___

### verifyOptions

• **verifyOptions**: `any`

Options passed to jwt.verify. See https://www.npmjs.com/package/jsonwebtoken

#### Defined in

[index.js:199](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L199)
