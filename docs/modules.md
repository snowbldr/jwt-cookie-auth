[Documentation](README.md) / Exports

# Documentation

## Table of contents

### Classes

- [HttpStatusError](classes/HttpStatusError.md)
- [JwtCookieAuthorizer](classes/JwtCookieAuthorizer.md)
- [JwtUser](classes/JwtUser.md)
- [LoginResult](classes/LoginResult.md)
- [PersistedUser](classes/PersistedUser.md)
- [UnauthorizedError](classes/UnauthorizedError.md)
- [User](classes/User.md)
- [UserLockEvent](classes/UserLockEvent.md)

### Interfaces

- [AuthRequest](interfaces/AuthRequest.md)
- [AuthResponse](interfaces/AuthResponse.md)
- [AuthorizerOptions](interfaces/AuthorizerOptions.md)
- [JwtKeys](interfaces/JwtKeys.md)
- [LockingOptions](interfaces/LockingOptions.md)
- [LoginOperations](interfaces/LoginOperations.md)
- [TokenOptions](interfaces/TokenOptions.md)
- [Tokens](interfaces/Tokens.md)

### Type Aliases

- [checkRefreshTokenValid](modules.md#checkrefreshtokenvalid)
- [hashPassword](modules.md#hashpassword)
- [invalidateRefreshToken](modules.md#invalidaterefreshtoken)
- [loadUserByUsername](modules.md#loaduserbyusername)
- [middleware](modules.md#middleware)
- [setLockStatus](modules.md#setlockstatus)
- [storeRefreshToken](modules.md#storerefreshtoken)
- [userToJwtPayload](modules.md#usertojwtpayload)

### Functions

- [createSha512Hmac](modules.md#createsha512hmac)
- [deleteCookies](modules.md#deletecookies)
- [getCookies](modules.md#getcookies)
- [hasAllRoles](modules.md#hasallroles)
- [hasAllRolesMiddleware](modules.md#hasallrolesmiddleware)
- [hasAnyRole](modules.md#hasanyrole)
- [hasAnyRoleMiddleware](modules.md#hasanyrolemiddleware)
- [setCookies](modules.md#setcookies)

## Type Aliases

### checkRefreshTokenValid

Ƭ **checkRefreshTokenValid**<\>: (`jwtUser`: [`JwtUser`](classes/JwtUser.md), `token`: `string`) => `Promise`<`void`\>

#### Type declaration

▸ (`jwtUser`, `token`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `jwtUser` | [`JwtUser`](classes/JwtUser.md) |
| `token` | `string` |

##### Returns

`Promise`<`void`\>

#### Defined in

[index.js:267](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L267)

___

### hashPassword

Ƭ **hashPassword**<\>: (`password`: `string`, `salt`: `string`) => `Promise`<`string`\>

#### Type declaration

▸ (`password`, `salt`): `Promise`<`string`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `password` | `string` |
| `salt` | `string` |

##### Returns

`Promise`<`string`\>

#### Defined in

[index.js:284](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L284)

___

### invalidateRefreshToken

Ƭ **invalidateRefreshToken**<\>: (`jwtUser`: [`JwtUser`](classes/JwtUser.md), `token`: `string`) => `Promise`<`void`\>

#### Type declaration

▸ (`jwtUser`, `token`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `jwtUser` | [`JwtUser`](classes/JwtUser.md) |
| `token` | `string` |

##### Returns

`Promise`<`void`\>

#### Defined in

[index.js:275](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L275)

___

### loadUserByUsername

Ƭ **loadUserByUsername**<\>: (`username`: `string`, `request`: [`AuthRequest`](interfaces/AuthRequest.md), `response`: [`AuthResponse`](interfaces/AuthResponse.md)) => `Promise`<[`PersistedUser`](classes/PersistedUser.md)\>

#### Type declaration

▸ (`username`, `request`, `response`): `Promise`<[`PersistedUser`](classes/PersistedUser.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |
| `request` | [`AuthRequest`](interfaces/AuthRequest.md) |
| `response` | [`AuthResponse`](interfaces/AuthResponse.md) |

##### Returns

`Promise`<[`PersistedUser`](classes/PersistedUser.md)\>

#### Defined in

[index.js:231](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L231)

___

### middleware

Ƭ **middleware**<\>: (`req`: `object`, `res`: `object`, `next`: function(*=): void) => `void`

#### Type declaration

▸ (`req`, `res`, `next`): `void`

##### Parameters

| Name | Type |
| :------ | :------ |
| `req` | `object` |
| `res` | `object` |
| `next` | function(*=): void |

##### Returns

`void`

#### Defined in

[index.js:339](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L339)

___

### setLockStatus

Ƭ **setLockStatus**<\>: (`userLockEvent`: [`UserLockEvent`](classes/UserLockEvent.md)) => `Promise`<`void`\>

#### Type declaration

▸ (`userLockEvent`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `userLockEvent` | [`UserLockEvent`](classes/UserLockEvent.md) |

##### Returns

`Promise`<`void`\>

#### Defined in

[index.js:308](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L308)

___

### storeRefreshToken

Ƭ **storeRefreshToken**<\>: (`jwtUser`: [`JwtUser`](classes/JwtUser.md), `token`: `string`) => `Promise`<`void`\>

#### Type declaration

▸ (`jwtUser`, `token`): `Promise`<`void`\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `jwtUser` | [`JwtUser`](classes/JwtUser.md) |
| `token` | `string` |

##### Returns

`Promise`<`void`\>

#### Defined in

[index.js:248](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L248)

___

### userToJwtPayload

Ƭ **userToJwtPayload**<\>: (`user`: [`PersistedUser`](classes/PersistedUser.md)) => `Promise`<[`JwtUser`](classes/JwtUser.md)\>

#### Type declaration

▸ (`user`): `Promise`<[`JwtUser`](classes/JwtUser.md)\>

##### Parameters

| Name | Type |
| :------ | :------ |
| `user` | [`PersistedUser`](classes/PersistedUser.md) |

##### Returns

`Promise`<[`JwtUser`](classes/JwtUser.md)\>

#### Defined in

[index.js:292](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L292)

## Functions

### createSha512Hmac

▸ **createSha512Hmac**(`value`, `salt`): `string`

Create a hmac sha512 hash of the given value and salt

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `value` | `string` | The value to hash |
| `salt` | `string` | A salt to use to create the hmac |

#### Returns

`string`

A base64 hash of the value

#### Defined in

[index.js:739](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L739)

___

### deleteCookies

▸ **deleteCookies**(`res`, ...`cookieNames`): `void`

Delete the user's cookies.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `res` | [`AuthResponse`](interfaces/AuthResponse.md) | The response object to set the cookies on |
| `...cookieNames` | `string`[] | The names of the cookies to add to the set-cookie header |

#### Returns

`void`

#### Defined in

[index.js:807](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L807)

___

### getCookies

▸ **getCookies**(`req`): `any`

Get the parsed cookies from the request

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `req` | [`AuthRequest`](interfaces/AuthRequest.md) | The request object to get cookies from |

#### Returns

`any`

An object containing the cookies by name

#### Defined in

[index.js:816](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L816)

___

### hasAllRoles

▸ **hasAllRoles**(`userRoles`, ...`requiredRoles`): `boolean`

Check whether the userRoles contains all the requiredRoles

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `userRoles` | `string`[] | An array of the roles the user is assigned |
| `...requiredRoles` | `string`[] | An array of the roles the user must have all of |

#### Returns

`boolean`

#### Defined in

[index.js:675](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L675)

___

### hasAllRolesMiddleware

▸ **hasAllRolesMiddleware**(...`requiredRoles`): [`middleware`](modules.md#middleware)

Create a middleware to validate the current user has all the required roles

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `...requiredRoles` | `string`[] | The roles the user must have all of |

#### Returns

[`middleware`](modules.md#middleware)

a new middleware function that reads the user's roles form req.user.roles and validates the user has all the required roles

#### Defined in

[index.js:707](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L707)

___

### hasAnyRole

▸ **hasAnyRole**(`userRoles`, ...`requiredRoles`): `boolean`

Check whether the userRoles contains at least one of the requiredRoles

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `userRoles` | `string`[] | An array of the roles the user is assigned |
| `...requiredRoles` | `string`[] | An array of the roles the user must have one of |

#### Returns

`boolean`

#### Defined in

[index.js:657](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L657)

___

### hasAnyRoleMiddleware

▸ **hasAnyRoleMiddleware**(...`requiredRoles`): [`middleware`](modules.md#middleware)

Create a middleware to validate the current user has any of the specified roles

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `...requiredRoles` | `string`[] | The roles the user must have one of |

#### Returns

[`middleware`](modules.md#middleware)

a new middleware function that reads the user's roles from req.user.roles and validates the user has any of required roles

#### Defined in

[index.js:692](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L692)

___

### setCookies

▸ **setCookies**(`res`, ...`cookies`): `void`

Set cookies on the response. The cookies should be serialized strings.
If there are existing values for set-cookie, they will not be overridden.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `res` | [`AuthResponse`](interfaces/AuthResponse.md) | The response object to set the cookies on |
| `...cookies` | `string`[] | The serialized cookies to add to the set-cookie header |

#### Returns

`void`

#### Defined in

[index.js:790](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L790)
