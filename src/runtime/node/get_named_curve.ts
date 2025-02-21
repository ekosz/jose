import { KeyObject, createPublicKey } from 'crypto'
import { JOSENotSupported } from '../../util/errors.js'
import { isCryptoKey, getKeyObject } from './webcrypto.js'
import isKeyObject from './is_key_object.js'

const p256 = Buffer.from([42, 134, 72, 206, 61, 3, 1, 7])
const p384 = Buffer.from([43, 129, 4, 0, 34])
const p521 = Buffer.from([43, 129, 4, 0, 35])
const secp256k1 = Buffer.from([43, 129, 4, 0, 10])

export const weakMap: WeakMap<KeyObject, string> = new WeakMap()

const namedCurveToJOSE = (namedCurve: string) => {
  switch (namedCurve) {
    case 'prime256v1':
      return 'P-256'
    case 'secp384r1':
      return 'P-384'
    case 'secp521r1':
      return 'P-521'
    case 'secp256k1':
      return namedCurve
    default:
      throw new JOSENotSupported('unsupported key curve for this operation')
  }
}

const getNamedCurve = (key: unknown, raw?: boolean): string => {
  if (isCryptoKey(key)) {
    // eslint-disable-next-line no-param-reassign
    key = getKeyObject(key)
  }
  if (!isKeyObject(key)) {
    throw new TypeError('invalid key input')
  }

  if (key.type === 'secret') {
    throw new TypeError('only "private" or "public" key objects can be used for this operation')
  }

  switch (key.asymmetricKeyType) {
    case 'ed25519':
    case 'ed448':
      return `Ed${key.asymmetricKeyType.substr(2)}`
    case 'x25519':
    case 'x448':
      return `X${key.asymmetricKeyType.substr(1)}`
    case 'ec': {
      if (weakMap.has(key)) {
        return weakMap.get(key)!
      }

      let namedCurve = key.asymmetricKeyDetails?.namedCurve

      if (!namedCurve && key.type === 'private') {
        namedCurve = getNamedCurve(createPublicKey(key), true)
      } else if (!namedCurve) {
        const buf = key.export({ format: 'der', type: 'spki' })
        const i = buf[1] < 128 ? 14 : 15
        const len = buf[i]
        const curveOid = buf.slice(i + 1, i + 1 + len)
        if (curveOid.equals(p256)) {
          namedCurve = 'prime256v1'
        } else if (curveOid.equals(p384)) {
          namedCurve = 'secp384r1'
        } else if (curveOid.equals(p521)) {
          namedCurve = 'secp521r1'
        } else if (curveOid.equals(secp256k1)) {
          namedCurve = 'secp256k1'
        } else {
          throw new JOSENotSupported('unsupported key curve for this operation')
        }
      }

      if (raw) return namedCurve

      const curve = namedCurveToJOSE(namedCurve)
      weakMap.set(key, curve)
      return curve
    }
    default:
      throw new TypeError('invalid key asymmetric key type for this operation')
  }
}

export function setCurve(keyObject: KeyObject, curve: string) {
  weakMap.set(keyObject, curve)
}

export default getNamedCurve
