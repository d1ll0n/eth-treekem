const { derive } = require('eccrypto')
const { 
  encryptWithPublicKey: ecEncryptWithPublicKey,
  decryptWithPrivateKey: ecDecryptWithPrivateKey,
  publicKeyByPrivateKey: publicKeyFromPrivateKey,
  publicKey: {
    decompress: decompressPubkey,
    toAddress: addressFromPublicKey
  },
  util: { removeTrailing0x },
  cipher: {
    parse: parseCipher,
    stringify: stringifyCipher
  }
} = require('eth-crypto')

function computeSecret(privateKey, publicKey) {
  const pubKey = '04' + decompressPubkey(publicKey)
  const privKey = removeTrailing0x(privateKey)
  return derive(Buffer.from(privKey, 'hex'), Buffer.from(pubKey, 'hex'))
}

function encryptWithPublicKey(publicKey, message, serialize = true) {
  const cipher = ecEncryptWithPublicKey(publicKey, message)
  return serialize ? stringifyCipher(cipher) : cipher
}

function decryptWithPrivateKey(cipher, privateKey) {
  const _cipher = typeof cipher == 'string' ? parseCipher(cipher) : cipher
  return ecDecryptWithPrivateKey(privateKey, _cipher)
}

module.exports = {
  computeSecret,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  publicKeyFromPrivateKey,
  addressFromPublicKey
}