import { KeyObject, publicEncrypt, constants, privateDecrypt } from 'crypto'
import type { RsaEsDecryptFunction, RsaEsEncryptFunction } from '../interfaces.d'
import checkModulusLength from './check_modulus_length.js'
import { isCryptoKey, getKeyObject } from './webcrypto.js'
import isKeyObject from './is_key_object.js'
import InvalidKeyInput from './invalid_key_input.js'

const checkKey = (key: KeyObject, alg: string) => {
  if (key.asymmetricKeyType !== 'rsa') {
    throw new TypeError('Invalid key for this operation, its asymmetricKeyType must be rsa')
  }
  checkModulusLength(key, alg)
}

const resolvePadding = (alg: string) => {
  switch (alg) {
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      return constants.RSA_PKCS1_OAEP_PADDING
    case 'RSA1_5':
      return constants.RSA_PKCS1_PADDING
    default:
      return undefined
  }
}

const resolveOaepHash = (alg: string) => {
  switch (alg) {
    case 'RSA-OAEP':
      return 'sha1'
    case 'RSA-OAEP-256':
      return 'sha256'
    case 'RSA-OAEP-384':
      return 'sha384'
    case 'RSA-OAEP-512':
      return 'sha512'
    default:
      return undefined
  }
}

function ensureKeyObject(key: unknown, alg: string, ...usages: KeyUsage[]) {
  if (isKeyObject(key)) {
    return key
  }
  if (isCryptoKey(key)) {
    return getKeyObject(key, alg, new Set(usages))
  }
  throw InvalidKeyInput(key, 'KeyObject', 'CryptoKey')
}

export const encrypt: RsaEsEncryptFunction = async (alg: string, key: unknown, cek: Uint8Array) => {
  const padding = resolvePadding(alg)
  const oaepHash = resolveOaepHash(alg)
  const keyObject = ensureKeyObject(key, alg, 'wrapKey', 'encrypt')

  checkKey(keyObject, alg)
  return publicEncrypt({ key: keyObject, oaepHash, padding }, cek)
}

export const decrypt: RsaEsDecryptFunction = async (
  alg: string,
  key: unknown,
  encryptedKey: Uint8Array,
) => {
  const padding = resolvePadding(alg)
  const oaepHash = resolveOaepHash(alg)
  const keyObject = ensureKeyObject(key, alg, 'unwrapKey', 'decrypt')

  checkKey(keyObject, alg)
  return privateDecrypt({ key: keyObject, oaepHash, padding }, encryptedKey)
}
