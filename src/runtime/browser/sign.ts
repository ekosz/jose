import type { SignFunction } from '../interfaces.d'
import subtleAlgorithm from './subtle_dsa.js'
import crypto from './webcrypto.js'
import checkKeyLength from './check_key_length.js'
import getSignKey from './get_sign_verify_key.js'

const sign: SignFunction = async (alg, key: unknown, data) => {
  const cryptoKey = await getSignKey(alg, key, 'sign')
  checkKeyLength(alg, cryptoKey)
  const signature = await crypto.subtle.sign(subtleAlgorithm(alg), cryptoKey, data)
  return new Uint8Array(signature)
}

export default sign
