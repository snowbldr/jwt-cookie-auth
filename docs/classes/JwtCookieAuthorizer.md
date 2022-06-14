[Documentation](../README.md) / [Exports](../modules.md) / JwtCookieAuthorizer

# Class: JwtCookieAuthorizer

An object that handles creating and authenticating JWTs

## Table of contents

### Constructors

- [constructor](JwtCookieAuthorizer.md#constructor)

### Properties

- [#config](JwtCookieAuthorizer.md##config)

### Methods

- [#logoutUnauthorized](JwtCookieAuthorizer.md##logoutunauthorized)
- [#verifyRequest](JwtCookieAuthorizer.md##verifyrequest)
- [authorizeMiddleware](JwtCookieAuthorizer.md#authorizemiddleware)
- [basicAuthLogin](JwtCookieAuthorizer.md#basicauthlogin)
- [basicAuthLoginMiddleware](JwtCookieAuthorizer.md#basicauthloginmiddleware)
- [getCookieValue](JwtCookieAuthorizer.md#getcookievalue)
- [login](JwtCookieAuthorizer.md#login)
- [logout](JwtCookieAuthorizer.md#logout)
- [logoutMiddleware](JwtCookieAuthorizer.md#logoutmiddleware)
- [parseBasicAuthHeader](JwtCookieAuthorizer.md#parsebasicauthheader)
- [refreshAuthCookie](JwtCookieAuthorizer.md#refreshauthcookie)
- [refreshAuthMiddleware](JwtCookieAuthorizer.md#refreshauthmiddleware)
- [verifyAuth](JwtCookieAuthorizer.md#verifyauth)

## Constructors

### constructor

• **new JwtCookieAuthorizer**(`authorizerOptions`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `authorizerOptions` | [`AuthorizerOptions`](../interfaces/AuthorizerOptions.md) | Options to configure the authorizer |

#### Defined in

[index.js:359](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L359)

## Properties

### #config

• `Private` **#config**: [`AuthorizerOptions`](../interfaces/AuthorizerOptions.md)

#### Defined in

[index.js:354](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L354)

## Methods

### #logoutUnauthorized

▸ `Private` **#logoutUnauthorized**(`req`, `res`, `fn`): `Promise`<`any`\>

Logout the user if an unauthorized error is thrown

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | The incoming request |
| `res` | [`AuthResponse`](../interfaces/AuthResponse.md) | The outgoing response |
| `fn` | () => `any` | The function to run and listen for [UnauthorizedError](UnauthorizedError.md) |

#### Returns

`Promise`<`any`\>

The return value from fn

#### Defined in

[index.js:639](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L639)

___

### #verifyRequest

▸ `Private` **#verifyRequest**(`req`, `res`, `tokenOptions`): `Promise`<[`JwtUser`](JwtUser.md)\>

Verify the provided jwt cookie and set request.user from the decoded jwt payload

**`throws`** {UnauthorizedError}

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | The incoming request |
| `res` | [`AuthResponse`](../interfaces/AuthResponse.md) | The outgoing response |
| `tokenOptions` | [`TokenOptions`](../interfaces/TokenOptions.md) | The token options to use to verify the token |

#### Returns

`Promise`<[`JwtUser`](JwtUser.md)\>

#### Defined in

[index.js:625](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L625)

___

### authorizeMiddleware

▸ **authorizeMiddleware**(): [`middleware`](../modules.md#middleware)

Create a new middleware function that will exchange basic auth for a jwt token or will validate an existing jwt

#### Returns

[`middleware`](../modules.md#middleware)

A middleware that will authorize the request using this authorizer

#### Defined in

[index.js:387](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L387)

___

### basicAuthLogin

▸ **basicAuthLogin**(`req`, `res`): `Promise`<`void`\>

Log the user in using a basic auth header

**`throws`** {UnauthorizedError}

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | The current request with a headers object containing the request headers |
| `res` | [`AuthResponse`](../interfaces/AuthResponse.md) | The current response to set the cookies on |

#### Returns

`Promise`<`void`\>

#### Defined in

[index.js:565](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L565)

___

### basicAuthLoginMiddleware

▸ **basicAuthLoginMiddleware**(): [`middleware`](../modules.md#middleware)

#### Returns

[`middleware`](../modules.md#middleware)

A middleware that will authorize the request using the provided authorizer

#### Defined in

[index.js:375](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L375)

___

### getCookieValue

▸ **getCookieValue**(`req`, `cookieName`): `string`

Get a cookie's value from the request

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | The current request |
| `cookieName` | `string` | The cookie's value to get |

#### Returns

`string`

#### Defined in

[index.js:593](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L593)

___

### login

▸ **login**(`user`, `password`): [`LoginResult`](LoginResult.md)

Attempt to log the user in and create a new jwt token

**`throws`** {UnauthorizedError}

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `user` | [`PersistedUser`](PersistedUser.md) | The user to log in |
| `password` | `string` | The plain text password to log the user in with |

#### Returns

[`LoginResult`](LoginResult.md)

#### Defined in

[index.js:429](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L429)

___

### logout

▸ **logout**(`req`, `res`): `Promise`<`void`\>

Log the current user out by deleting their cookies and calling invalidateRefreshToken

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | The current request |
| `res` | [`AuthResponse`](../interfaces/AuthResponse.md) | The current response |

#### Returns

`Promise`<`void`\>

#### Defined in

[index.js:508](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L508)

___

### logoutMiddleware

▸ **logoutMiddleware**(): [`middleware`](../modules.md#middleware)

Create a middleware that will log out the user when called

#### Returns

[`middleware`](../modules.md#middleware)

#### Defined in

[index.js:414](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L414)

___

### parseBasicAuthHeader

▸ **parseBasicAuthHeader**(`authHeader`): `Object`

**`throws`** {UnauthorizedError}

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `authHeader` | `string` | The authorization header value from the request |

#### Returns

`Object`

| Name | Type |
| :------ | :------ |
| `password` | `string` |
| `username` | `string` |

#### Defined in

[index.js:602](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L602)

___

### refreshAuthCookie

▸ **refreshAuthCookie**(`req`, `res`, `reloadUser?`): `Promise`<`void`\>

Exchange a valid jwt token for a new one with a later expiration time
The request must contain a valid auth token and a valid refresh token (if refresh is enabled) to be accepted
You must refresh the auth cookie before either token expires to keep the session active
If either token is expired, the user must re-login
The new jwt is added as a cookie which overwrites the existing cookie

**`throws`** {UnauthorizedError}

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | `undefined` | The current request object |
| `res` | [`AuthResponse`](../interfaces/AuthResponse.md) | `undefined` | The current response object |
| `reloadUser` | `boolean` | `false` | Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data |

#### Returns

`Promise`<`void`\>

#### Defined in

[index.js:537](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L537)

___

### refreshAuthMiddleware

▸ **refreshAuthMiddleware**(`reloadUser?`): [`middleware`](../modules.md#middleware)

Create a new middleware function that will exchange a valid jwt for a newer valid jwt

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `reloadUser` | `boolean` | `false` | Whether to call loadUserByUsername to reload a user's data. Useful to refresh user roles or other identity data |

#### Returns

[`middleware`](../modules.md#middleware)

A middleware to refresh jwt token cookies

#### Defined in

[index.js:400](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L400)

___

### verifyAuth

▸ **verifyAuth**(`req`, `res`): `Promise`<[`JwtUser`](JwtUser.md)\>

Verify the provided jwt cookie and set the user on the request to the parser user in the jwt

**`throws`** {UnauthorizedError}

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](../interfaces/AuthRequest.md) | The incoming request |
| `res` | [`AuthResponse`](../interfaces/AuthResponse.md) | The outgoing response |

#### Returns

`Promise`<[`JwtUser`](JwtUser.md)\>

#### Defined in

[index.js:498](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L498)
