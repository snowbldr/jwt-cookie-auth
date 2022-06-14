[Documentation](../README.md) / [Exports](../modules.md) / JwtKeys

# Interface: JwtKeys<\>

## Table of contents

### Properties

- [private](JwtKeys.md#private)
- [public](JwtKeys.md#public)

## Properties

### private

• **private**: `string` \| `Buffer`

The private key passed to sign from https://www.npmjs.com/package/jsonwebtoken
If not passed, it will not be possible to generate new tokens.

#### Defined in

[index.js:185](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L185)

___

### public

• **public**: `string` \| `Buffer`

The public key passed to verify from https://www.npmjs.com/package/jsonwebtoken

#### Defined in

[index.js:187](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L187)
