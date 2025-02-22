# Class: JWEDecryptionFailed

[util/errors](../modules/util_errors.md).JWEDecryptionFailed

An error subclass thrown when a JWE ciphertext decryption fails.

## Hierarchy

- [JOSEError](util_errors.joseerror.md)

  ↳ **JWEDecryptionFailed**

## Table of contents

### Constructors

- [constructor](util_errors.jwedecryptionfailed.md#constructor)

### Properties

- [code](util_errors.jwedecryptionfailed.md#code)
- [message](util_errors.jwedecryptionfailed.md#message)
- [code](util_errors.jwedecryptionfailed.md#code)

## Constructors

### constructor

• **new JWEDecryptionFailed**(`message?`)

#### Parameters

| Name | Type |
| :------ | :------ |
| `message?` | `string` |

#### Inherited from

[JOSEError](util_errors.joseerror.md).[constructor](util_errors.joseerror.md#constructor)

#### Defined in

[util/errors.ts:16](https://github.com/panva/jose/blob/v3.13.0/src/util/errors.ts#L16)

## Properties

### code

• **code**: `string`

A unique error code for the particular error subclass.

#### Overrides

[JOSEError](util_errors.joseerror.md).[code](util_errors.joseerror.md#code)

#### Defined in

[util/errors.ts:77](https://github.com/panva/jose/blob/v3.13.0/src/util/errors.ts#L77)

___

### message

• **message**: `string` = 'decryption operation failed'

#### Overrides

JOSEError.message

#### Defined in

[util/errors.ts:79](https://github.com/panva/jose/blob/v3.13.0/src/util/errors.ts#L79)

___

### code

▪ `Static` **code**: `string` = 'ERR\_JWE\_DECRYPTION\_FAILED'

A unique error code for the particular error subclass.

#### Overrides

[JOSEError](util_errors.joseerror.md).[code](util_errors.joseerror.md#code)

#### Defined in

[util/errors.ts:75](https://github.com/panva/jose/blob/v3.13.0/src/util/errors.ts#L75)
