// generate-keys.js
const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const defaultDir = "./bk-keys"

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

if (!fs.existsSync(defaultDir)) fs.mkdirSync(defaultDir);
fs.writeFileSync(`${defaultDir}/public.pem`, publicKey);

if (!fs.existsSync("public")) fs.mkdirSync("public");
fs.writeFileSync(`public/public.pem`, publicKey);
fs.writeFileSync(`${defaultDir}/private.pem`, privateKey);

console.log(`🔐 Chaves RSA geradas em ${defaultDir}`);
