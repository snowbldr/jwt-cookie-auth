[Documentation](../README.md) / [Exports](../modules.md) / AuthResponse

# Interface: AuthResponse<\>

Minimal required properties of a response object as used by JwtCookieAuthorizer

## Table of contents

### Properties

- [end](AuthResponse.md#end)
- [get](AuthResponse.md#get)
- [getHeader](AuthResponse.md#getheader)
- [set](AuthResponse.md#set)
- [setHeader](AuthResponse.md#setheader)
- [statusCode](AuthResponse.md#statuscode)
- [statusMessage](AuthResponse.md#statusmessage)

## Properties

### end

• **end**: `Function`

End the current response

#### Defined in

[index.js:171](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L171)

___

### get

• **get**: (`header`: `string`) => `string` \| `string`[]

#### Type declaration

▸ (`header`): `string` \| `string`[]

return the value of a header (available in frameworks like express)

##### Parameters

| Name | Type |
| :------ | :------ |
| `header` | `string` |

##### Returns

`string` \| `string`[]

#### Defined in

[index.js:166](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L166)

___

### getHeader

• **getHeader**: (`header`: `string`) => `string` \| `string`[]

#### Type declaration

▸ (`header`): `string` \| `string`[]

return the value of a header

##### Parameters

| Name | Type |
| :------ | :------ |
| `header` | `string` |

##### Returns

`string` \| `string`[]

#### Defined in

[index.js:165](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L165)

___

### set

• **set**: (`header`: `string`) => `void`

#### Type declaration

▸ (`header`): `void`

set the value of a header (available in frameworks like express)

##### Parameters

| Name | Type |
| :------ | :------ |
| `header` | `string` |

##### Returns

`void`

#### Defined in

[index.js:168](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L168)

___

### setHeader

• **setHeader**: (`header`: `string`) => `void`

#### Type declaration

▸ (`header`): `void`

set the value of a header

##### Parameters

| Name | Type |
| :------ | :------ |
| `header` | `string` |

##### Returns

`void`

#### Defined in

[index.js:167](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L167)

___

### statusCode

• **statusCode**: `number`

Used to set the HTTP response status code

#### Defined in

[index.js:169](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L169)

___

### statusMessage

• **statusMessage**: `string`

Used to set the HTTP response status message

#### Defined in

[index.js:170](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L170)
