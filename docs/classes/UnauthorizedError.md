[Documentation](../README.md) / [Exports](../modules.md) / UnauthorizedError

# Class: UnauthorizedError

An HttpError with 401 statusCode and Unauthorized statusMessage

**`property`** {*=} [body] An object or message to use as the response body

**`property`** {Error=} [cause] The error that caused this error to be thrown, if any

## Hierarchy

- [`HttpStatusError`](HttpStatusError.md)

  ↳ **`UnauthorizedError`**

## Table of contents

### Constructors

- [constructor](UnauthorizedError.md#constructor)

### Properties

- [body](UnauthorizedError.md#body)
- [message](UnauthorizedError.md#message)
- [name](UnauthorizedError.md#name)
- [stack](UnauthorizedError.md#stack)
- [statusCode](UnauthorizedError.md#statuscode)
- [statusMessage](UnauthorizedError.md#statusmessage)
- [prepareStackTrace](UnauthorizedError.md#preparestacktrace)
- [stackTraceLimit](UnauthorizedError.md#stacktracelimit)

### Methods

- [captureStackTrace](UnauthorizedError.md#capturestacktrace)

## Constructors

### constructor

• **new UnauthorizedError**(`body`, `cause`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `body` | `any` |
| `cause` | `Error` |

#### Overrides

[HttpStatusError](HttpStatusError.md).[constructor](HttpStatusError.md#constructor)

#### Defined in

[index.js:777](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L777)

## Properties

### body

• **body**: `any`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[body](HttpStatusError.md#body)

#### Defined in

[index.js:762](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L762)

___

### message

• **message**: `string`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[message](HttpStatusError.md#message)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1029

___

### name

• **name**: `string`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[name](HttpStatusError.md#name)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1028

___

### stack

• `Optional` **stack**: `string`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[stack](HttpStatusError.md#stack)

#### Defined in

node_modules/typescript/lib/lib.es5.d.ts:1030

___

### statusCode

• **statusCode**: `number`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[statusCode](HttpStatusError.md#statuscode)

#### Defined in

[index.js:760](https://github.com/snowbldr/jwt-cookie-auth/blob/fc7d646/index.js#L760)

___

### statusMessage

• **statusMessage**: `string`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[statusMessage](HttpStatusError.md#statusmessage)

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

[HttpStatusError](HttpStatusError.md).[prepareStackTrace](HttpStatusError.md#preparestacktrace)

#### Defined in

node_modules/@types/node/globals.d.ts:11

___

### stackTraceLimit

▪ `Static` **stackTraceLimit**: `number`

#### Inherited from

[HttpStatusError](HttpStatusError.md).[stackTraceLimit](HttpStatusError.md#stacktracelimit)

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

[HttpStatusError](HttpStatusError.md).[captureStackTrace](HttpStatusError.md#capturestacktrace)

#### Defined in

node_modules/@types/node/globals.d.ts:4
