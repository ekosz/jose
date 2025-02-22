# Interface: FlattenedDecryptGetKey

[jwe/flattened/decrypt](../modules/jwe_flattened_decrypt.md).FlattenedDecryptGetKey

## Hierarchy

- [GetKeyFunction](types.getkeyfunction.md)<[JWEHeaderParameters](types.jweheaderparameters.md) \| undefined, [FlattenedJWE](types.flattenedjwe.md)\>

  ↳ **FlattenedDecryptGetKey**

## Callable

### FlattenedDecryptGetKey

▸ **FlattenedDecryptGetKey**(`protectedHeader`, `token`): `Promise`<[KeyLike](../types/types.keylike.md)\>

Interface for Flattened JWE Decryption dynamic key resolution.
No token components have been verified at the time of this function call.

#### Parameters

| Name | Type |
| :------ | :------ |
| `protectedHeader` | `undefined` \| [JWEHeaderParameters](types.jweheaderparameters.md) |
| `token` | [FlattenedJWE](types.flattenedjwe.md) |

#### Returns

`Promise`<[KeyLike](../types/types.keylike.md)\>

#### Defined in

[types.d.ts:78](https://github.com/panva/jose/blob/v3.13.0/src/types.d.ts#L78)
