import * as crypto from 'crypto'
import { isCryptoKey, getKeyObject } from './webcrypto.js'
import getSecretKey from './secret_key.js'
import InvalidKeyInput from './invalid_key_input.js'

export default function getSignVerifyKey(alg: string, key: unknown, usage: KeyUsage) {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith('HS')) {
      throw InvalidKeyInput(key, 'KeyObject', 'CryptoKey')
    }
    return getSecretKey(key)
  }
  if (key instanceof crypto.KeyObject) {
    return key
  }
  if (isCryptoKey(key)) {
    return getKeyObject(key, alg, new Set([usage]))
  }
  throw InvalidKeyInput(key, 'KeyObject', 'CryptoKey', 'Buffer', 'Uint8Array')
}
