import crypto, { isCryptoKey } from './webcrypto.js'
import InvalidKeyInput from './invalid_key_input.js'

export default function getCryptoKey(alg: string, key: unknown, usage: KeyUsage) {
  if (isCryptoKey(key)) {
    return key
  }

  if (key instanceof Uint8Array) {
    if (!alg.startsWith('HS')) {
      throw InvalidKeyInput(key, 'CryptoKey')
    }
    return crypto.subtle.importKey(
      'raw',
      key,
      { hash: { name: `SHA-${alg.substr(-3)}` }, name: 'HMAC' },
      false,
      [usage],
    )
  }

  throw InvalidKeyInput(key, 'CryptoKey', 'Uint8Array')
}
