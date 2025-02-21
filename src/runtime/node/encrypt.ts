import { KeyObject, createCipheriv } from 'crypto'
import type { CipherGCMTypes } from 'crypto'

import type { EncryptFunction } from '../interfaces.d'
import checkIvLength from '../../lib/check_iv_length.js'
import checkCekLength from './check_cek_length.js'
import { concat } from '../../lib/buffer_utils.js'
import cbcTag from './cbc_tag.js'
import type { KeyLike } from '../../types.d'
import { isCryptoKey, getKeyObject } from './webcrypto.js'
import isKeyObject from './is_key_object.js'

async function cbcEncrypt(
  enc: string,
  plaintext: Uint8Array,
  cek: KeyObject | Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
) {
  const keySize = parseInt(enc.substr(1, 3), 10)

  if (isKeyObject(cek)) {
    // eslint-disable-next-line no-param-reassign
    cek = cek.export()
  }

  const encKey = cek.subarray(keySize >> 3)
  const macKey = cek.subarray(0, keySize >> 3)

  const algorithm = `aes-${keySize}-cbc`
  const cipher = createCipheriv(algorithm, encKey, iv)
  const ciphertext = concat(cipher.update(plaintext), cipher.final())

  const macSize = parseInt(enc.substr(-3), 10)
  const tag = cbcTag(aad, iv, ciphertext, macSize, macKey, keySize)

  return { ciphertext, tag }
}
async function gcmEncrypt(
  enc: string,
  plaintext: Uint8Array,
  cek: KeyObject | Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
) {
  const keySize = parseInt(enc.substr(1, 3), 10)

  const algorithm = <CipherGCMTypes>`aes-${keySize}-gcm`
  const cipher = createCipheriv(algorithm, cek, iv, { authTagLength: 16 })
  if (aad.byteLength) {
    cipher.setAAD(aad)
  }

  const ciphertext = concat(cipher.update(plaintext), cipher.final())
  const tag = cipher.getAuthTag()

  return { ciphertext, tag }
}

const encrypt: EncryptFunction = async (
  enc: string,
  plaintext: Uint8Array,
  cek: unknown,
  iv: Uint8Array,
  aad: Uint8Array,
) => {
  let key: KeyLike
  if (isCryptoKey(cek)) {
    // eslint-disable-next-line no-param-reassign
    key = getKeyObject(cek, enc, new Set(['encrypt']))
  } else if (cek instanceof Uint8Array || isKeyObject(cek)) {
    key = cek
  } else {
    throw new TypeError('invalid key input')
  }

  checkCekLength(enc, key)
  checkIvLength(enc, iv)

  if (enc.substr(4, 3) === 'CBC') {
    return cbcEncrypt(enc, plaintext, key, iv, aad)
  }

  return gcmEncrypt(enc, plaintext, key, iv, aad)
}

export default encrypt
