import test from 'ava';

let root;
let keyRoot;

if ('WEBCRYPTO' in process.env) {
  root = keyRoot = '#dist/webcrypto';
} else if ('CRYPTOKEY' in process.env) {
  root = '#dist';
  keyRoot = '#dist/webcrypto';
} else {
  root = keyRoot = '#dist';
}

Promise.all([
  import(`${root}/lib/check_key_type`),
  import(`${keyRoot}/util/generate_key_pair`),
  import(`${keyRoot}/util/generate_secret`),
]).then(
  ([{ default: checkKeyType }, { default: generateKeyPair }, { default: generateSecret }]) => {
    test('lib/check_key_type.ts', async (t) => {
      const { privateKey, publicKey } = await generateKeyPair('RSA-OAEP');
      const secret = await generateSecret('HS256');

      t.throws(() => checkKeyType('HS256', privateKey), {
        instanceOf: TypeError,
        message:
          'CryptoKey or KeyObject instances for symmetric algorithms must be of type "secret"',
      });
      t.throws(() => checkKeyType('HS256', publicKey), {
        instanceOf: TypeError,
        message:
          'CryptoKey or KeyObject instances for symmetric algorithms must be of type "secret"',
      });
      t.throws(() => checkKeyType('RSA-OAEP', new Uint8Array(0)), {
        instanceOf: TypeError,
        message: 'CryptoKey or KeyObject instances must be used for asymmetric algorithms',
      });
      t.throws(() => checkKeyType('RSA-OAEP', secret), {
        instanceOf: TypeError,
        message:
          'CryptoKey or KeyObject instances for asymmetric algorithms must not be of type "secret"',
      });

      t.notThrows(() => checkKeyType('HS256', secret));
      t.notThrows(() => checkKeyType('RSA-OAEP', publicKey));
      t.notThrows(() => checkKeyType('RSA-OAEP', privateKey));
    });
  },
  (err) => {
    test('failed to import', (t) => {
      console.error(err);
      t.fail();
    });
  },
);
