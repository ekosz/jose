# Interface: JWTDecryptGetKey

[jwt/decrypt](../modules/jwt_decrypt.md).JWTDecryptGetKey

## Hierarchy

- [GetKeyFunction](types.getkeyfunction.md)<[JWEHeaderParameters](types.jweheaderparameters.md), [FlattenedJWE](types.flattenedjwe.md)\>

  ↳ **JWTDecryptGetKey**

## Callable

### JWTDecryptGetKey

▸ **JWTDecryptGetKey**(`protectedHeader`, `token`): `Promise`<[KeyLike](../types/types.keylike.md)\>

Interface for JWT Decryption dynamic key resolution.
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
