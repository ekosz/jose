# Function: EmbeddedJWK

[jwk/embedded](../modules/jwk_embedded.md).EmbeddedJWK

▸ **EmbeddedJWK**(`protectedHeader`, `token`): `Promise`<KeyObject \| CryptoKey\>

EmbeddedJWK is an implementation of a GetKeyFunction intended to be used with the
JWS/JWT verify operations whenever you need to opt-in to verify signatures with
a public key embedded in the token's "jwk" (JSON Web Key) Header Parameter.
It is recommended to combine this with the verify algorithms option to whitelist
JWS algorithms to accept.

**`example`** ESM import
```js
import { EmbeddedJWK } from 'jose/jwk/embedded'
```

**`example`** CJS import
```js
const { EmbeddedJWK } = require('jose/jwk/embedded')
```

**`example`** Usage
```js
import { jwtVerify } from 'jose/jwt/verify'

const jwt = 'eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJ4IjoiVU05ZzVuS25aWFlvdldBbE03NmNMejl2VG96UmpfX0NIVV9kT2wtZ09vRSIsInkiOiJkczhhZVF3MWwyY0RDQTdiQ2tPTnZ3REtwWEFidFhqdnFDbGVZSDhXc19VIiwia3R5IjoiRUMifSwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJhdWQiOiJ1cm46ZXhhbXBsZTphdWRpZW5jZSIsImlhdCI6MTYwNDU4MDc5NH0.60boak3_dErnW47ZPty1C0nrjeVq86EN_eK0GOq6K8w2OA0thKoBxFK4j-NuU9yZ_A9UKGxPT_G87DladBaV9g'

const { payload, protectedHeader } = await jwtVerify(jwt, EmbeddedJWK, {
  issuer: 'urn:example:issuer',
  audience: 'urn:example:audience'
})

console.log(protectedHeader)
console.log(payload)
```

#### Parameters

| Name | Type |
| :------ | :------ |
| `protectedHeader` | [JWSHeaderParameters](../interfaces/types.jwsheaderparameters.md) |
| `token` | [FlattenedJWSInput](../interfaces/types.flattenedjwsinput.md) |

#### Returns

`Promise`<KeyObject \| CryptoKey\>

#### Defined in

[jwk/embedded.ts:40](https://github.com/panva/jose/blob/v3.13.0/src/jwk/embedded.ts#L40)
