const fs = require('fs');
const forge = require('node-forge');
const crypto = require('crypto');

const privateKeyPem = fs.readFileSync('bk-keys/private.pem', 'utf8');
const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

const recentNonces = new Set();

function decryptAESKey(encryptedKeyB64) {
  const encryptedBytes = forge.util.decode64(encryptedKeyB64);
  const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP', {
    md: forge.md.sha256.create() // 🔥 ESSENCIAL!
  });
  return Buffer.from(decrypted, 'binary');
}


function decryptAESGCM(encryptedDataB64, key, ivB64, authTagB64) {
  const encrypted = Buffer.from(encryptedDataB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, null, 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

function processEncryptedPayload({ encryptedData, encryptedKey, iv, authTag, timestamp, nonce }) {
  // Verificação de tempo (máx 30s)
  const now = Date.now();
  if (Math.abs(now - timestamp) > 30000) {
    throw new Error('Timestamp muito antigo ou do futuro');
  }

  // Verificação de nonce duplicado
  if (recentNonces.has(nonce)) {
    throw new Error('Nonce já usado (possível ataque de repetição)');
  }

  // Salva nonce por 30s (simples)
  recentNonces.add(nonce);
  setTimeout(() => recentNonces.delete(nonce), 30000);

  const aesKey = decryptAESKey(encryptedKey);
  const plaintext = decryptAESGCM(encryptedData, aesKey, iv, authTag);

  console.log('🔓 Mensagem recebida:', plaintext);
  return plaintext;
}

module.exports = { processEncryptedPayload };
