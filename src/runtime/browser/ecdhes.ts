import type {
  EcdhAllowedFunction,
  EcdhESDeriveKeyFunction,
  GenerateEpkFunction,
} from '../interfaces.d'
import { encoder, concat, uint32be, lengthAndInput, concatKdf } from '../../lib/buffer_utils.js'
import crypto, { isCryptoKey } from './webcrypto.js'
import digest from './digest.js'
import InvalidKeyInput from './invalid_key_input.js'

export const deriveKey: EcdhESDeriveKeyFunction = async (
  publicKey: unknown,
  privateKey: unknown,
  algorithm: string,
  keyLength: number,
  apu: Uint8Array = new Uint8Array(0),
  apv: Uint8Array = new Uint8Array(0),
) => {
  if (!isCryptoKey(publicKey)) {
    throw InvalidKeyInput(publicKey, 'CryptoKey')
  }
  if (!isCryptoKey(privateKey)) {
    throw InvalidKeyInput(privateKey, 'CryptoKey')
  }

  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  )

  if (!privateKey.usages.includes('deriveBits')) {
    throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"')
  }

  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey,
      },
      privateKey,
      Math.ceil(parseInt((<EcKeyAlgorithm>privateKey.algorithm).namedCurve.substr(-3), 10) / 8) <<
        3,
    ),
  )

  return concatKdf(digest, sharedSecret, keyLength, value)
}

export const generateEpk: GenerateEpkFunction = async (key: unknown) => {
  if (!isCryptoKey(key)) {
    throw InvalidKeyInput(key, 'CryptoKey')
  }

  return (
    await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: (<EcKeyAlgorithm>key.algorithm).namedCurve },
      true,
      ['deriveBits'],
    )
  ).privateKey
}

export const ecdhAllowed: EcdhAllowedFunction = (key: unknown) => {
  if (!isCryptoKey(key)) {
    throw InvalidKeyInput(key, 'CryptoKey')
  }
  return ['P-256', 'P-384', 'P-521'].includes((<EcKeyAlgorithm>key.algorithm).namedCurve)
}
