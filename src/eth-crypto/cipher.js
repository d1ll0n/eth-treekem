const crypto = require('crypto')

const CBC = 'aes-256-cbc'
const GCM = 'aes-256-gcm'

const hash = data => crypto.createHash('sha256').update(data).digest()
const randomBytes = crypto.randomBytes
const newIv = () => randomBytes(16)

function encrypt(algorithm, data, password) {
  const iv = newIv()
  const key = hash(password)
  const _cipher = crypto.createCipheriv(algorithm, key, iv)
  const cipher = _cipher.update(data, 'utf8', 'hex') + _cipher.final('hex')
  return {
    algorithm,
    cipher,
    iv
  }
}

function decrypt(_cipher, password) {
  const { cipher, iv, algorithm } = _cipher
  const key = hash(password)
  const _decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv))
  let decipher = _decipher.update(cipher, 'hex', 'utf8') + _decipher.final('utf8')
  return decipher
}

const cbcEncrypt = (data, password) => encrypt(CBC, data, password)
const gcmEncrypt = (data, password) => encrypt(GCM, data, password)

module.exports = {
  encrypt,
  cbcEncrypt,
  gcmEncrypt,
  decrypt,
  hash: data => hash(data).toString('hex'),
  randomBytes
}