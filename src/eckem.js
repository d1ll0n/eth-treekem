'use strict';

const EC = require('./eth-crypto');

/*
 * Arguments:
 *   plaintext: The value to be encrypted, as a BufferSource
 *   pub:       Public key for the receiver
 *
 * Returns: Promise resolving to an ECKEMCiphertext object:
 *   {
 *     pub: CryptoKey
 *     iv: BufferSource
 *     ct: BufferSource
 *   }
 */
async function encrypt(pt, pubA) {
  const kpE = EC.newKeyPair()
  const secret = await kpE.computeSecret(pubA)
  const cipher = EC.cbcEncrypt(pt, secret)
  console.log('------plaintext------')
  console.log(pt)
  return JSON.stringify({ pub: kpE.publicKey, cipher })
}

/*
 * Arguments:
 *   ciphertext: The value to be decrypted, as an object
 *   priv:       Private key for the receiver
 *
 * Returns: Promise<ArrayBuffer>
 */
async function decrypt(_cipherData, priv) {
  const cipherData = typeof _cipherData == 'string' ? JSON.parse(_cipherData) : _cipherData
  const { cipher, pub } = cipherData
  const secret = await EC.computeSecret(priv, pub)
  const pt = EC.decrypt(cipher, secret)
  console.log('------decipher-------')
  console.log(pt)
  return pt
}

/*
 * Self-test: Encrypt/decrypt round trip
 */
async function test() {
  const original = '01234'
  const kp = EC.newKeyPair();

  try {
    const encrypted = await encrypt(original, kp.publicKey);
    const decrypted = await decrypt(encrypted, kp.privateKey);
    const equal = decrypted == original
    console.log("[ECKEM]", equal? "PASS" : "FAIL");
  } catch (err) {
    console.log("[ECKEM] FAIL:", err);
  }
}

module.exports = {
  encrypt,
  decrypt,
  test,
}
