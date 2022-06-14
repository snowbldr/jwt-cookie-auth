[Documentation](../README.md) / [Exports](../modules.md) / JwtUser

# Class: JwtUser

Minimal JWT user data

## Hierarchy

- [`User`](User.md)

  ↳ **`JwtUser`**

## Table of contents

### Constructors

- [constructor](JwtUser.md#constructor)

### Properties

- [roles](JwtUser.md#roles)
- [sub](JwtUser.md#sub)
- [username](JwtUser.md#username)

## Constructors

### constructor

• **new JwtUser**(`opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Object` |
| `opts.roles` | `string`[] |
| `opts.sub` | `string` |
| `opts.username` | `string` |

#### Overrides

[User](User.md).[constructor](User.md#constructor)

#### Defined in

[index.js:43](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L43)

## Properties

### roles

• **roles**: `string`[]

Roles assigned to the user

#### Inherited from

[User](User.md).[roles](User.md#roles)

#### Defined in

[index.js:19](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L19)

___

### sub

• **sub**: `string`

The user's unique name, synonym for username

#### Defined in

[index.js:38](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L38)

___

### username

• **username**: `string`

The user's unique name

#### Inherited from

[User](User.md).[username](User.md#username)

#### Defined in

[index.js:14](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L14)
