# Interface: GeneralJWS

[types](../modules/types.md).GeneralJWS

General JWS definition. Payload is an optional return property, it
is not returned when JWS Unencoded Payload Option
[RFC7797](https://tools.ietf.org/html/rfc7797) is used.

## Table of contents

### Properties

- [payload](types.generaljws.md#payload)
- [signatures](types.generaljws.md#signatures)

## Properties

### payload

• `Optional` **payload**: `string`

#### Defined in

[types.d.ts:226](https://github.com/panva/jose/blob/v3.13.0/src/types.d.ts#L226)

___

### signatures

• **signatures**: `Omit`<[FlattenedJWSInput](types.flattenedjwsinput.md), ``"payload"``\>[]

#### Defined in

[types.d.ts:227](https://github.com/panva/jose/blob/v3.13.0/src/types.d.ts#L227)
