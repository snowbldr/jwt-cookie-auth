[Documentation](../README.md) / [Exports](../modules.md) / UserLockEvent

# Class: UserLockEvent

## Table of contents

### Constructors

- [constructor](UserLockEvent.md#constructor)

### Properties

- [action](UserLockEvent.md#action)
- [failedLogins](UserLockEvent.md#failedlogins)
- [lockedAt](UserLockEvent.md#lockedat)
- [username](UserLockEvent.md#username)

## Constructors

### constructor

• **new UserLockEvent**(`opts`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | `Object` |
| `opts.action` | `string` |
| `opts.failedLogins` | `number` |
| `opts.lockedAt` | `Date` |
| `opts.username` | `string` |

#### Defined in

[index.js:113](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L113)

## Properties

### action

• **action**: `string`

The action that triggered the {@link AuthorizerOptions.setLockStatus} function, one of ('failedAttempt', 'locked', 'unlocked')

#### Defined in

[index.js:97](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L97)

___

### failedLogins

• **failedLogins**: `number`

The number of failed login attempts so far

#### Defined in

[index.js:102](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L102)

___

### lockedAt

• **lockedAt**: `Date`

The point in time when this user became locked

#### Defined in

[index.js:107](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L107)

___

### username

• **username**: `string`

The user's unique name

#### Defined in

[index.js:92](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L92)
