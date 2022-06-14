[Documentation](../README.md) / [Exports](../modules.md) / HttpStatusError

# Class: HttpStatusError

An Error with an associated http statusCode and statusMessage

**`property`** {number} statusCode Http status code associated with the exception

**`property`** {string} statusMessage The status message to use on the response

**`property`** {*=} [body] An object or message to use as the response body

## Hierarchy

- `Error`

  ↳ **`HttpStatusError`**

  ↳↳ [`UnauthorizedError`](UnauthorizedError.md)

## Table of contents

### Constructors

- [constructor](HttpStatusError.md#constructor)

### Properties

- [body](HttpStatusError.md#body)
- [message](HttpStatusError.md#message)
- [name](HttpStatusError.md#name)
- [stack](HttpStatusError.md#stack)
- [statusCode](HttpStatusError.md#statuscode)
- [statusMessage](HttpStatusError.md#statusmessage)
- [prepareStackTrace](HttpStatusError.md#preparestacktrace)
- [stackTraceLimit](HttpStatusError.md#stacktracelimit)

### Methods

- [captureStackTrace](HttpStatusError.md#capturestacktrace)

## Constructors

### constructor

• **new HttpStatusError**(`statusCode`, `statusMessage`, `body`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `statusCode` | `number` |
| `statusMessage` | `string` |
| `body` | `any` |

#### Overrides

Error.constructor

#### Defined in

[index.js:758](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L758)

## Properties

### body

• **body**: `any`

#### Defined in

[index.js:762](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L762)

___

### message

• **message**: `string`

#### Inherited from

Error.message

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1029

___

### name

• **name**: `string`

#### Inherited from

Error.name

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1028

___

### stack

• `Optional` **stack**: `string`

#### Inherited from

Error.stack

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1030

___

### statusCode

• **statusCode**: `number`

#### Defined in

[index.js:760](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L760)

___

### statusMessage

• **statusMessage**: `string`

#### Defined in

[index.js:761](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L761)

___

### prepareStackTrace

▪ `Static` `Optional` **prepareStackTrace**: (`err`: `Error`, `stackTraces`: `CallSite`[]) => `any`

#### Type declaration

▸ (`err`, `stackTraces`): `any`

Optional override for formatting stack traces

**`see`** https://v8.dev/docs/stack-trace-api#customizing-stack-traces

##### Parameters

| Name | Type |
| :------ | :------ |
| `err` | `Error` |
| `stackTraces` | `CallSite`[] |

##### Returns

`any`

#### Inherited from

Error.prepareStackTrace

#### Defined in

node_modules/@types/node/globals.d.ts:11

___

### stackTraceLimit

▪ `Static` **stackTraceLimit**: `number`

#### Inherited from

Error.stackTraceLimit

#### Defined in

node_modules/@types/node/globals.d.ts:13

## Methods

### captureStackTrace

▸ `Static` **captureStackTrace**(`targetObject`, `constructorOpt?`): `void`

Create .stack property on a target object

#### Parameters

| Name | Type |
| :------ | :------ |
| `targetObject` | `object` |
| `constructorOpt?` | `Function` |

#### Returns

`void`

#### Inherited from

Error.captureStackTrace

#### Defined in

node_modules/@types/node/globals.d.ts:4
