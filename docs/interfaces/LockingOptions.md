[Documentation](../README.md) / [Exports](../modules.md) / LockingOptions

# Interface: LockingOptions<\>

## Table of contents

### Properties

- [lockSeconds](LockingOptions.md#lockseconds)
- [maxFailedLogins](LockingOptions.md#maxfailedlogins)
- [setLockStatus](LockingOptions.md#setlockstatus)

## Properties

### lockSeconds

• **lockSeconds**: `number`

Number of seconds to lock the user after reaching the max failed attempts. Defaults to 10 minutes.

#### Defined in

[index.js:301](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L301)

___

### maxFailedLogins

• **maxFailedLogins**: `number`

Maximum number of login attempts to allow before locking the user. Defaults to 10.

#### Defined in

[index.js:300](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L300)

___

### setLockStatus

• **setLockStatus**: [`setLockStatus`](../modules.md#setlockstatus)

Set the user's lock status

#### Defined in

[index.js:302](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L302)
