'use strict';

const EC = require('./eth-crypto')

function iota(secret) {
  const digest = EC.hash(secret)
  const keyPair = EC.keyPairFromPrivate(digest)

  return keyPair
}

async function test() {
  const key = EC.newKeyPair()
  const secret = await key.computeSecret(key.publicKey)
  const kp = iota(secret)
  console.log(kp)
}

module.exports = iota;
