import { JOSEAlgNotAllowed, JOSENotSupported, JWEInvalid } from '../../util/errors.js'
import isDisjoint from '../../lib/is_disjoint.js'
import isObject from '../../lib/is_object.js'

import { decode as base64url } from '../../runtime/base64url.js'
import decrypt from '../../runtime/decrypt.js'
import { inflate } from '../../runtime/zlib.js'
import decryptKeyManagement from '../../lib/decrypt_key_management.js'

import type {
  FlattenedDecryptResult,
  KeyLike,
  FlattenedJWE,
  JWEHeaderParameters,
  DecryptOptions,
  GetKeyFunction,
} from '../../types.d'
import { encoder, decoder, concat } from '../../lib/buffer_utils.js'
import cekFactory from '../../lib/cek.js'
import random from '../../runtime/random.js'
import validateCrit from '../../lib/validate_crit.js'
import validateAlgorithms from '../../lib/validate_algorithms.js'

const generateCek = cekFactory(random)
const checkExtensions = validateCrit.bind(undefined, JWEInvalid, new Map())
const checkAlgOption = validateAlgorithms.bind(undefined, 'keyManagementAlgorithms')
const checkEncOption = validateAlgorithms.bind(undefined, 'contentEncryptionAlgorithms')

/**
 * Interface for Flattened JWE Decryption dynamic key resolution.
 * No token components have been verified at the time of this function call.
 */
export interface FlattenedDecryptGetKey
  extends GetKeyFunction<JWEHeaderParameters | undefined, FlattenedJWE> {}

/**
 * Decrypts a Flattened JWE.
 *
 * @param jwe Flattened JWE.
 * @param key Public Key or Secret, or a function resolving one, to decrypt the JWE with.
 * @param options JWE Decryption options.
 *
 * @example ESM import
 * ```js
 * import { flattenedDecrypt } from 'jose/jwe/flattened/decrypt'
 * ```
 *
 * @example CJS import
 * ```js
 * const { flattenedDecrypt } = require('jose/jwe/flattened/decrypt')
 * ```
 *
 * @example Usage
 * ```js
 * const decoder = new TextDecoder()
 * const jwe = {
 *   ciphertext: '9EzjFISUyoG-ifC2mSihfP0DPC80yeyrxhTzKt1C_VJBkxeBG0MI4Te61Pk45RAGubUvBpU9jm4',
 *   iv: '8Fy7A_IuoX5VXG9s',
 *   tag: 'W76IYV6arGRuDSaSyWrQNg',
 *   encrypted_key: 'Z6eD4UK_yFb5ZoKvKkGAdqywEG_m0e4IYo0x8Vf30LAMJcsc-_zSgIeiF82teZyYi2YYduHKoqImk7MRnoPZOlEs0Q5BNK1OgBmSOhCE8DFyqh9Zh48TCTP6lmBQ52naqoUJFMtHzu-0LwZH26hxos0GP3Dt19O379MJB837TdKKa87skq0zHaVLAquRHOBF77GI54Bc7O49d8aOrSu1VEFGMThlW2caspPRiTSePDMDPq7_WGk50izRhB3Asl9wmP9wEeaTrkJKRnQj5ips1SAZ1hDBsqEQKKukxP1HtdcopHV5_qgwU8Hjm5EwSLMluMQuiE6hwlkXGOujZLVizA',
 *   aad: 'VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc',
 *   protected: 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0'
 * }
 *
 * const {
 *   plaintext,
 *   protectedHeader,
 *   additionalAuthenticatedData
 * } = await flattenedDecrypt(jwe, privateKey)
 *
 * console.log(protectedHeader)
 * console.log(decoder.decode(plaintext))
 * console.log(decoder.decode(additionalAuthenticatedData))
 * ```
 */
async function flattenedDecrypt(
  jwe: FlattenedJWE,
  key: KeyLike | FlattenedDecryptGetKey,
  options?: DecryptOptions,
): Promise<FlattenedDecryptResult> {
  if (!isObject(jwe)) {
    throw new JWEInvalid('Flattened JWE must be an object')
  }

  if (jwe.protected === undefined && jwe.header === undefined && jwe.unprotected === undefined) {
    throw new JWEInvalid('JOSE Header missing')
  }

  if (typeof jwe.iv !== 'string') {
    throw new JWEInvalid('JWE Initialization Vector missing or incorrect type')
  }

  if (typeof jwe.ciphertext !== 'string') {
    throw new JWEInvalid('JWE Ciphertext missing or incorrect type')
  }

  if (typeof jwe.tag !== 'string') {
    throw new JWEInvalid('JWE Authentication Tag missing or incorrect type')
  }

  if (jwe.protected !== undefined && typeof jwe.protected !== 'string') {
    throw new JWEInvalid('JWE Protected Header incorrect type')
  }

  if (jwe.encrypted_key !== undefined && typeof jwe.encrypted_key !== 'string') {
    throw new JWEInvalid('JWE Encrypted Key incorrect type')
  }

  if (jwe.aad !== undefined && typeof jwe.aad !== 'string') {
    throw new JWEInvalid('JWE AAD incorrect type')
  }

  if (jwe.header !== undefined && !isObject(jwe.header)) {
    throw new JWEInvalid('JWE Shared Unprotected Header incorrect type')
  }

  if (jwe.unprotected !== undefined && !isObject(jwe.unprotected)) {
    throw new JWEInvalid('JWE Per-Recipient Unprotected Header incorrect type')
  }

  let parsedProt!: JWEHeaderParameters
  if (jwe.protected) {
    const protectedHeader = base64url(jwe.protected)
    parsedProt = JSON.parse(decoder.decode(protectedHeader))
  }
  if (!isDisjoint(parsedProt, jwe.header, jwe.unprotected)) {
    throw new JWEInvalid(
      'JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint',
    )
  }

  const joseHeader: JWEHeaderParameters = {
    ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected,
  }

  checkExtensions(options?.crit, parsedProt, joseHeader)

  if (joseHeader.zip !== undefined) {
    if (!parsedProt || !parsedProt.zip) {
      throw new JWEInvalid('JWE "zip" (Compression Algorithm) Header MUST be integrity protected')
    }

    if (joseHeader.zip !== 'DEF') {
      throw new JOSENotSupported(
        'unsupported JWE "zip" (Compression Algorithm) Header Parameter value',
      )
    }
  }

  const { alg, enc } = joseHeader

  if (typeof alg !== 'string' || !alg) {
    throw new JWEInvalid('missing JWE Algorithm (alg) in JWE Header')
  }

  if (typeof enc !== 'string' || !enc) {
    throw new JWEInvalid('missing JWE Encryption Algorithm (enc) in JWE Header')
  }

  const keyManagementAlgorithms = options && checkAlgOption(options.keyManagementAlgorithms)
  const contentEncryptionAlgorithms = options && checkEncOption(options.contentEncryptionAlgorithms)

  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg)) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter not allowed')
  }

  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
    throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter not allowed')
  }

  let encryptedKey!: Uint8Array
  if (jwe.encrypted_key !== undefined) {
    encryptedKey = base64url(jwe.encrypted_key!)
  }

  if (typeof key === 'function') {
    // eslint-disable-next-line no-param-reassign
    key = await key(parsedProt, jwe)
  }

  let cek: KeyLike
  try {
    cek = await decryptKeyManagement(alg, key, encryptedKey, joseHeader)
  } catch (err) {
    if (err instanceof TypeError) {
      throw err
    }
    // https://tools.ietf.org/html/rfc7516#section-11.5
    // To mitigate the attacks described in RFC 3218, the
    // recipient MUST NOT distinguish between format, padding, and length
    // errors of encrypted keys.  It is strongly recommended, in the event
    // of receiving an improperly formatted key, that the recipient
    // substitute a randomly generated CEK and proceed to the next step, to
    // mitigate timing attacks.
    cek = generateCek(enc)
  }

  const iv = base64url(jwe.iv)
  const tag = base64url(jwe.tag)

  const protectedHeader: Uint8Array = encoder.encode(jwe.protected ?? '')
  let additionalData: Uint8Array

  if (jwe.aad !== undefined) {
    additionalData = concat(protectedHeader, encoder.encode('.'), encoder.encode(jwe.aad))
  } else {
    additionalData = protectedHeader
  }

  let plaintext = await decrypt(enc, cek, base64url(jwe.ciphertext), iv, tag, additionalData)

  if (joseHeader.zip === 'DEF') {
    plaintext = await (options?.inflateRaw || inflate)(plaintext)
  }

  const result: FlattenedDecryptResult = { plaintext }

  if (jwe.protected !== undefined) {
    result.protectedHeader = parsedProt
  }

  if (jwe.aad !== undefined) {
    result.additionalAuthenticatedData = base64url(jwe.aad!)
  }

  if (jwe.unprotected !== undefined) {
    result.sharedUnprotectedHeader = jwe.unprotected
  }

  if (jwe.header !== undefined) {
    result.unprotectedHeader = jwe.header
  }

  return result
}

export { flattenedDecrypt }
export default flattenedDecrypt
export type { KeyLike, FlattenedJWE, JWEHeaderParameters, DecryptOptions, FlattenedDecryptResult }
