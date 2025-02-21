# Class: CompactEncrypt

[jwe/compact/encrypt](../modules/jwe_compact_encrypt.md).CompactEncrypt

The CompactEncrypt class is a utility for creating Compact JWE strings.

**`example`** ESM import
```js
import { CompactEncrypt } from 'jose/jwe/compact/encrypt'
```

**`example`** CJS import
```js
const { CompactEncrypt } = require('jose/jwe/compact/encrypt')
```

**`example`** Usage
```js
const encoder = new TextEncoder()

const jwe = await new CompactEncrypt(encoder.encode('It’s a dangerous business, Frodo, going out your door.'))
  .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
  .encrypt(publicKey)

console.log(jwe)
```

## Table of contents

### Constructors

- [constructor](jwe_compact_encrypt.compactencrypt.md#constructor)

### Methods

- [encrypt](jwe_compact_encrypt.compactencrypt.md#encrypt)
- [setContentEncryptionKey](jwe_compact_encrypt.compactencrypt.md#setcontentencryptionkey)
- [setInitializationVector](jwe_compact_encrypt.compactencrypt.md#setinitializationvector)
- [setKeyManagementParameters](jwe_compact_encrypt.compactencrypt.md#setkeymanagementparameters)
- [setProtectedHeader](jwe_compact_encrypt.compactencrypt.md#setprotectedheader)

## Constructors

### constructor

• **new CompactEncrypt**(`plaintext`)

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `plaintext` | `Uint8Array` | Binary representation of the plaintext to encrypt. |

#### Defined in

[jwe/compact/encrypt.ts:34](https://github.com/panva/jose/blob/v3.13.0/src/jwe/compact/encrypt.ts#L34)

## Methods

### encrypt

▸ **encrypt**(`key`, `options?`): `Promise`<string\>

Encrypts and resolves the value of the Compact JWE string.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | [KeyLike](../types/types.keylike.md) | Public Key or Secret to encrypt the JWE with. |
| `options?` | [EncryptOptions](../interfaces/types.encryptoptions.md) | JWE Encryption options. |

#### Returns

`Promise`<string\>

#### Defined in

[jwe/compact/encrypt.ts:97](https://github.com/panva/jose/blob/v3.13.0/src/jwe/compact/encrypt.ts#L97)

___

### setContentEncryptionKey

▸ **setContentEncryptionKey**(`cek`): [CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

Sets a content encryption key to use, by default a random suitable one
is generated for the JWE enc" (Encryption Algorithm) Header Parameter.
You do not need to invoke this method, it is only really intended for
test and vector validation purposes.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `cek` | `Uint8Array` | JWE Content Encryption Key. |

#### Returns

[CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

#### Defined in

[jwe/compact/encrypt.ts:51](https://github.com/panva/jose/blob/v3.13.0/src/jwe/compact/encrypt.ts#L51)

___

### setInitializationVector

▸ **setInitializationVector**(`iv`): [CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

Sets the JWE Initialization Vector to use for content encryption, by default
a random suitable one is generated for the JWE enc" (Encryption Algorithm)
Header Parameter. You do not need to invoke this method, it is only really
intended for test and vector validation purposes.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `iv` | `Uint8Array` | JWE Initialization Vector. |

#### Returns

[CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

#### Defined in

[jwe/compact/encrypt.ts:64](https://github.com/panva/jose/blob/v3.13.0/src/jwe/compact/encrypt.ts#L64)

___

### setKeyManagementParameters

▸ **setKeyManagementParameters**(`parameters`): [CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

Sets the JWE Key Management parameters to be used when encrypting the Content
Encryption Key. You do not need to invoke this method, it is only really
intended for test and vector validation purposes.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `parameters` | [JWEKeyManagementHeaderParameters](../interfaces/types.jwekeymanagementheaderparameters.md) | JWE Key Management parameters. |

#### Returns

[CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

#### Defined in

[jwe/compact/encrypt.ts:86](https://github.com/panva/jose/blob/v3.13.0/src/jwe/compact/encrypt.ts#L86)

___

### setProtectedHeader

▸ **setProtectedHeader**(`protectedHeader`): [CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

Sets the JWE Protected Header on the CompactEncrypt object.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `protectedHeader` | [JWEHeaderParameters](../interfaces/types.jweheaderparameters.md) | JWE Protected Header object. |

#### Returns

[CompactEncrypt](jwe_compact_encrypt.compactencrypt.md)

#### Defined in

[jwe/compact/encrypt.ts:74](https://github.com/panva/jose/blob/v3.13.0/src/jwe/compact/encrypt.ts#L74)
