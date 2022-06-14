[Documentation](../README.md) / [Exports](../modules.md) / PersistedUser

# Class: PersistedUser

Minimal data for a persisted user capable of logging in

## Hierarchy

- [`User`](User.md)

  ↳ **`PersistedUser`**

## Table of contents

### Constructors

- [constructor](PersistedUser.md#constructor)

### Properties

- [failedLogins](PersistedUser.md#failedlogins)
- [lockedAt](PersistedUser.md#lockedat)
- [passwordHash](PersistedUser.md#passwordhash)
- [roles](PersistedUser.md#roles)
- [salt](PersistedUser.md#salt)
- [username](PersistedUser.md#username)

## Constructors

### constructor

• **new PersistedUser**(`opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Object` |
| `opts.failedLogins` | `number` |
| `opts.lockedAt` | `Date` |
| `opts.passwordHash` | `string` |
| `opts.roles` | `string`[] |
| `opts.salt` | `string` |
| `opts.username` | `string` |

#### Overrides

[User](User.md).[constructor](User.md#constructor)

#### Defined in

[index.js:78](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L78)

## Properties

### failedLogins

• **failedLogins**: `number`

The number of failed login attempts so far

#### Defined in

[index.js:67](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L67)

___

### lockedAt

• **lockedAt**: `Date`

The point in time when this user became locked

#### Defined in

[index.js:72](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L72)

___

### passwordHash

• **passwordHash**: `string`

A hash of the user's password and their salt

#### Defined in

[index.js:57](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L57)

___

### roles

• **roles**: `string`[]

Roles assigned to the user

#### Inherited from

[User](User.md).[roles](User.md#roles)

#### Defined in

[index.js:19](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L19)

___

### salt

• **salt**: `string`

A random unique string used to make the same password hash to a different value and prevent identifying shared passwords based on the hash

#### Defined in

[index.js:62](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L62)

___

### username

• **username**: `string`

The user's unique name

#### Inherited from

[User](User.md).[username](User.md#username)

#### Defined in

[index.js:14](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L14)
