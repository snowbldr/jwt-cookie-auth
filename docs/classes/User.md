[Documentation](../README.md) / [Exports](../modules.md) / User

# Class: User

## Hierarchy

- **`User`**

  ↳ [`JwtUser`](JwtUser.md)

  ↳ [`PersistedUser`](PersistedUser.md)

## Table of contents

### Constructors

- [constructor](User.md#constructor)

### Properties

- [roles](User.md#roles)
- [username](User.md#username)

## Constructors

### constructor

• **new User**(`opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Object` |
| `opts.roles` | `string`[] |
| `opts.username` | `string` |

#### Defined in

[index.js:24](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L24)

## Properties

### roles

• **roles**: `string`[]

Roles assigned to the user

#### Defined in

[index.js:19](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L19)

___

### username

• **username**: `string`

The user's unique name

#### Defined in

[index.js:14](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L14)
