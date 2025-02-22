# Function: jwtDecrypt

[jwt/decrypt](../modules/jwt_decrypt.md).jwtDecrypt

▸ **jwtDecrypt**(`jwt`, `key`, `options?`): `Promise`<[JWTDecryptResult](../interfaces/types.jwtdecryptresult.md)\>

Verifies the JWT format (to be a JWE Compact format), decrypts the ciphertext, validates the JWT Claims Set.

**`example`** ESM import
```js
import { jwtDecrypt } from 'jose/jwt/decrypt'
```

**`example`** CJS import
```js
const { jwtDecrypt } = require('jose/jwt/decrypt')
```

**`example`** Usage
```js
const jwt = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..KVcNLqK-3-8ZkYIC.xSwF4VxO0kUMUD2W-cifsNUxnr-swyBq-nADBptyt6y9n79-iNc5b0AALJpRwc0wwDkJw8hNOMjApNUTMsK9b-asToZ3DXFMvwfJ6n1aWefvd7RsoZ2LInWFfVAuttJDzoGB.uuexQoWHwrLMEYRElT8pBQ'

const { payload, protectedHeader } = await jwtDecrypt(jwt, secretKey, {
  issuer: 'urn:example:issuer',
  audience: 'urn:example:audience'
})

console.log(protectedHeader)
console.log(payload)
```

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `jwt` | `string` \| `Uint8Array` | JSON Web Token value (encoded as JWE). |
| `key` | [KeyLike](../types/types.keylike.md) \| [JWTDecryptGetKey](../interfaces/jwt_decrypt.jwtdecryptgetkey.md) | Private Key or Secret, or a function resolving one, to decrypt and verify the JWT with. |
| `options?` | [JWTDecryptOptions](../interfaces/jwt_decrypt.jwtdecryptoptions.md) | JWT Decryption and JWT Claims Set validation options. |

#### Returns

`Promise`<[JWTDecryptResult](../interfaces/types.jwtdecryptresult.md)\>

#### Defined in

[jwt/decrypt.ts:56](https://github.com/panva/jose/blob/v3.13.0/src/jwt/decrypt.ts#L56)
