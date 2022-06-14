[Documentation](../README.md) / [Exports](../modules.md) / Tokens

# Interface: Tokens<\>

## Table of contents

### Properties

- [auth](Tokens.md#auth)
- [refresh](Tokens.md#refresh)

## Properties

### auth

• **auth**: [`TokenOptions`](TokenOptions.md)

A token with a short expiration used for validating a user is authenticated. An expiresIn of 15m is used if not specified.
expiresIn should be set to the maximum amount of time a session is allowed to remain idle.

#### Defined in

[index.js:207](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L207)

___

### refresh

• **refresh**: [`TokenOptions`](TokenOptions.md)

A token with a long expiration used to refresh auth tokens. An expiresIn of 3d is used if not specified.
expiresIn should be set to the maximum amount of time a user is allowed to be logged in for without re-authorizing.
These tokens should be persisted, and removed when the user logs out, ending their session and preventing new tokens
from being created. The  function is used to store the token when it's
created, and the  function is used when the user is logged out to
remove or mark the refresh token as invalid.

#### Defined in

[index.js:209](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L209)
