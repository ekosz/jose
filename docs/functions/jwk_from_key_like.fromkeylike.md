# Function: fromKeyLike

[jwk/from_key_like](../modules/jwk_from_key_like.md).fromKeyLike

▸ **fromKeyLike**(`key`): `Promise`<[JWK](../interfaces/types.jwk.md)\>

Converts a runtime-specific key representation (KeyLike) to a JWK.

**`example`** ESM import
```js
import { fromKeyLike } from 'jose/jwk/from_key_like'
```

**`example`** CJS import
```js
const { fromKeyLike } = require('jose/jwk/from_key_like')
```

**`example`** Usage
```js
const privateJwk = await fromKeyLike(privateKey)
const publicJwk = await fromKeyLike(publicKey)

console.log(privateJwk)
console.log(publicJwk)
```

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `key` | [KeyLike](../types/types.keylike.md) | Key representation to transform to a JWK. |

#### Returns

`Promise`<[JWK](../interfaces/types.jwk.md)\>

#### Defined in

[jwk/from_key_like.ts:29](https://github.com/panva/jose/blob/v3.13.0/src/jwk/from_key_like.ts#L29)
