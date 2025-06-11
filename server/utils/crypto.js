const crypto = require('crypto');

// Generate RSA key pair
function generateRSAKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    return { publicKey, privateKey };
}

// AES-256-GCM Encrypt
function encrypt(message, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(message, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return {
        iv: iv.toString('hex'),
        ciphertext: encrypted.toString('hex'),
        tag: cipher.getAuthTag().toString('hex') // MUST include tag
    };
}

// AES-256-GCM Decrypt
function decrypt(cipherObj, key) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(cipherObj.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(cipherObj.tag, 'hex'));
    let decrypted = decipher.update(Buffer.from(cipherObj.ciphertext, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Generate ECDH keys
function generateECDHKeys() {
    const ecdh = crypto.createECDH('secp521r1');
    ecdh.generateKeys();
    return {
        publicKey: ecdh.getPublicKey().toString('hex'),
        privateKey: ecdh.getPrivateKey().toString('hex')
    };
}

// Compute shared secret
function computeSharedSecret(privateKey, publicKey) {
    const ecdh = crypto.createECDH('secp521r1');
    ecdh.setPrivateKey(Buffer.from(privateKey, 'hex'));
    return ecdh.computeSecret(publicKey, 'hex');
}

// Sign data with RSA private key
function signData(data, privateKey) {
    const sign = crypto.createSign('sha256');
    sign.update(data);
    return sign.sign(privateKey, 'hex');
}

// Verify signature
function verifySignature(data, signature, publicKey) {
    const verify = crypto.createVerify('sha256');
    verify.update(data);
    return verify.verify(publicKey, signature, 'hex');
}

module.exports = {
    generateRSAKeyPair,
    encrypt,
    decrypt,
    generateECDHKeys,
    computeSharedSecret,
    signData,
    verifySignature
};