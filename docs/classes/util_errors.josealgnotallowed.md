# Class: JOSEAlgNotAllowed

[util/errors](../modules/util_errors.md).JOSEAlgNotAllowed

An error subclass thrown when a JOSE Algorithm is not allowed per developer preference.

## Hierarchy

- [JOSEError](util_errors.joseerror.md)

  ↳ **JOSEAlgNotAllowed**

## Table of contents

### Constructors

- [constructor](util_errors.josealgnotallowed.md#constructor)

### Properties

- [code](util_errors.josealgnotallowed.md#code)
- [code](util_errors.josealgnotallowed.md#code)

## Constructors

### constructor

• **new JOSEAlgNotAllowed**(`message?`)

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

[util/errors.ts:58](https://github.com/panva/jose/blob/v3.13.0/src/util/errors.ts#L58)

___

### code

▪ `Static` **code**: `string` = 'ERR\_JOSE\_ALG\_NOT\_ALLOWED'

A unique error code for the particular error subclass.

#### Overrides

[JOSEError](util_errors.joseerror.md).[code](util_errors.joseerror.md#code)

#### Defined in

[util/errors.ts:56](https://github.com/panva/jose/blob/v3.13.0/src/util/errors.ts#L56)
