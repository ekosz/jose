import type { AesGcmKwWrapFunction, AesGcmKwUnwrapFunction } from '../interfaces.d'
import encrypt from './encrypt.js'
import decrypt from './decrypt.js'
import ivFactory from '../../lib/iv.js'
import random from './random.js'
import { encode as base64url } from './base64url.js'

const generateIv = ivFactory(random)

export const wrap: AesGcmKwWrapFunction = async (
  alg: string,
  key: unknown,
  cek: Uint8Array,
  iv?: Uint8Array,
) => {
  const jweAlgorithm = alg.substr(0, 7)
  // eslint-disable-next-line no-param-reassign
  iv ||= generateIv(jweAlgorithm)

  const { ciphertext: encryptedKey, tag } = await encrypt(
    jweAlgorithm,
    cek,
    key,
    iv,
    new Uint8Array(0),
  )

  return { encryptedKey, iv: base64url(iv), tag: base64url(tag) }
}

export const unwrap: AesGcmKwUnwrapFunction = async (
  alg: string,
  key: unknown,
  encryptedKey: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
) => {
  const jweAlgorithm = alg.substr(0, 7)

  return decrypt(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0))
}
