# Interface: GeneralDecryptGetKey

[jwe/general/decrypt](../modules/jwe_general_decrypt.md).GeneralDecryptGetKey

## Hierarchy

- [GetKeyFunction](types.getkeyfunction.md)<[JWEHeaderParameters](types.jweheaderparameters.md), [FlattenedJWE](types.flattenedjwe.md)\>

  ↳ **GeneralDecryptGetKey**

## Callable

### GeneralDecryptGetKey

▸ **GeneralDecryptGetKey**(`protectedHeader`, `token`): `Promise`<[KeyLike](../types/types.keylike.md)\>

Interface for General JWE Decryption dynamic key resolution.
No token components have been verified at the time of this function call.

#### Parameters

| Name | Type |
| :------ | :------ |
| `protectedHeader` | [JWEHeaderParameters](types.jweheaderparameters.md) |
| `token` | [FlattenedJWE](types.flattenedjwe.md) |

#### Returns

`Promise`<[KeyLike](../types/types.keylike.md)\>

#### Defined in

[types.d.ts:78](https://github.com/panva/jose/blob/v3.13.0/src/types.d.ts#L78)
