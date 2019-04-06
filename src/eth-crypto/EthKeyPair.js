const { createIdentity } = require('eth-crypto')
const { 
  computeSecret,encryptWithPublicKey, decryptWithPrivateKey,
  publicKeyFromPrivateKey, addressFromPublicKey
} = require('./ecUtil')

class EthKeyPair {
  constructor(identity = createIdentity()) { this.identity = identity }

  get privateKey() { return this.identity.privateKey }
  get publicKey() { return this.identity.publicKey }
  get address() { return this.identity.address }

  computeSecret(publicKey) {
    return computeSecret(this.privateKey, publicKey)
  }

  encryptForPubkey(publicKey, message, serialize = true) {
    return encryptWithPublicKey(publicKey, message, serialize)
  }

  decryptWithPrivKey() {
    return decryptWithPrivateKey(_cipher, this.privateKey)
  }
}

function keyPairFromPrivate(pvtKey) {
  const privateKey = pvtKey.toString('hex')
  const publicKey = publicKeyFromPrivateKey(privateKey)
  const address = addressFromPublicKey(publicKey)
  const identity = { address, publicKey, privateKey }
  return new EthKeyPair(identity)
}

module.exports = {
  EthKeyPair,
  keyPairFromPrivate,
  newKeyPair: () => new EthKeyPair()
}