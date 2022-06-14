[Documentation](../README.md) / [Exports](../modules.md) / AuthRequest

# Interface: AuthRequest<\>

Minimal required properties of a request object as used by JwtCookieAuthorizer

## Table of contents

### Properties

- [cookies](AuthRequest.md#cookies)
- [headers](AuthRequest.md#headers)
- [user](AuthRequest.md#user)

## Properties

### cookies

• **cookies**: `any`

Parsed cookies received on the request, cookies are parsed from the header if not available

#### Defined in

[index.js:176](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L176)

___

### headers

• **headers**: `any`

Headers received on the request

#### Defined in

[index.js:177](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L177)

___

### user

• **user**: `any`

The user object retrieved from the jwt

#### Defined in

[index.js:178](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L178)
