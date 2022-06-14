[Documentation](../README.md) / [Exports](../modules.md) / LoginResult

# Class: LoginResult

## Table of contents

### Constructors

- [constructor](LoginResult.md#constructor)

### Properties

- [authCookie](LoginResult.md#authcookie)
- [authToken](LoginResult.md#authtoken)
- [jwtUser](LoginResult.md#jwtuser)
- [refreshCookie](LoginResult.md#refreshcookie)
- [refreshToken](LoginResult.md#refreshtoken)

## Constructors

### constructor

• **new LoginResult**(`opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Object` |
| `opts.authCookie` | `string` |
| `opts.authToken` | `string` |
| `opts.jwtUser` | [`JwtUser`](JwtUser.md) |
| `opts.refreshCookie` | `string` |
| `opts.refreshToken` | `string` |

#### Defined in

[index.js:154](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L154)

## Properties

### authCookie

• **authCookie**: `string`

A cookie containing the authToken

#### Defined in

[index.js:136](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L136)

___

### authToken

• **authToken**: `string`

A JWT token to be used for authentication

#### Defined in

[index.js:131](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L131)

___

### jwtUser

• **jwtUser**: [`JwtUser`](JwtUser.md)

The user data that was encoded in the JWTs

#### Defined in

[index.js:126](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L126)

___

### refreshCookie

• **refreshCookie**: `string`

A cookie containing the authToken
only provided if refresh is enabled

#### Defined in

[index.js:148](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L148)

___

### refreshToken

• **refreshToken**: `string`

A JWT token to be used for obtaining new auth tokens
only provided if refresh is enabled

#### Defined in

[index.js:142](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L142)
