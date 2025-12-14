/**
 * Módulo responsável por processar payloads criptografados
 * utilizando criptografia híbrida (RSA + AES-GCM),
 * com proteção contra replay attack (timestamp + nonce).
 */

/* ===================== DEPENDÊNCIAS ===================== */

const fs = require('fs');          // Leitura de arquivos (chave privada)
const forge = require('node-forge'); // Operações criptográficas RSA
const crypto = require('crypto');   // Criptografia AES nativa do Node.js

/* ===================== CHAVE PRIVADA RSA ===================== */

// Lê a chave privada RSA do disco (formato PEM)
const privateKeyPem = fs.readFileSync('bk-keys/private.pem', 'utf8');

// Converte a chave PEM para objeto utilizável pelo node-forge
const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

/* ===================== CONTROLE DE NONCES ===================== */

// Armazena nonces recentemente utilizados para evitar replay attack
const recentNonces = new Set();

/* ===================== FUNÇÕES CRIPTOGRÁFICAS ===================== */

/**
 * Descriptografa a chave AES usando RSA-OAEP + SHA-256
 *
 * @param {string} encryptedKeyB64 - Chave AES criptografada em Base64
 * @returns {Buffer} Chave AES descriptografada
 */
function decryptAESKey(encryptedKeyB64) {
  // Converte Base64 para bytes
  const encryptedBytes = forge.util.decode64(encryptedKeyB64);

  // Descriptografa usando RSA-OAEP com SHA-256
  const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP', {
    md: forge.md.sha256.create() // ESSENCIAL para compatibilidade e segurança
  });

  // Retorna a chave AES como Buffer
  return Buffer.from(decrypted, 'binary');
}

/**
 * Descriptografa dados usando AES-256-GCM
 *
 * @param {string} encryptedDataB64 - Dados criptografados em Base64
 * @param {Buffer} key - Chave AES
 * @param {string} ivB64 - Vetor de inicialização (IV) em Base64
 * @param {string} authTagB64 - Tag de autenticação GCM em Base64
 * @returns {string} Texto descriptografado
 */
function decryptAESGCM(encryptedDataB64, key, ivB64, authTagB64) {
  // Converte entradas Base64 para Buffer
  const encrypted = Buffer.from(encryptedDataB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');

  // Cria o decipher AES-256-GCM
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

  // Define a tag de autenticação (garante integridade)
  decipher.setAuthTag(authTag);

  // Descriptografa os dados
  let decrypted = decipher.update(encrypted, null, 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/* ===================== FUNÇÃO PRINCIPAL ===================== */

/**
 * Processa um payload criptografado com validações de segurança
 *
 * @param {Object} payload - Objeto contendo os dados criptografados
 * @param {string} payload.encryptedData - Dados criptografados (Base64)
 * @param {string} payload.encryptedKey - Chave AES criptografada (Base64)
 * @param {string} payload.iv - IV do AES-GCM (Base64)
 * @param {string} payload.authTag - AuthTag do AES-GCM (Base64)
 * @param {number} payload.timestamp - Timestamp em ms
 * @param {string} payload.nonce - Identificador único da mensagem
 * @returns {string} Mensagem descriptografada
 */
function processEncryptedPayload({
  encryptedData,
  encryptedKey,
  iv,
  authTag,
  timestamp,
  nonce
}) {
  /* ===== Validação de tempo ===== */

  const now = Date.now();

  // Rejeita mensagens fora da janela de 30 segundos
  if (Math.abs(now - timestamp) > 30000) {
    throw new Error('Timestamp muito antigo ou do futuro');
  }

  /* ===== Proteção contra replay attack ===== */

  // Verifica se o nonce já foi usado
  if (recentNonces.has(nonce)) {
    throw new Error('Nonce já usado (possível ataque de repetição)');
  }

  // Armazena o nonce temporariamente
  recentNonces.add(nonce);

  // Remove o nonce após 30 segundos
  setTimeout(() => recentNonces.delete(nonce), 30000);

  /* ===== Descriptografia ===== */

  // Descriptografa a chave AES com RSA
  const aesKey = decryptAESKey(encryptedKey);

  // Descriptografa os dados com AES-GCM
  const plaintext = decryptAESGCM(encryptedData, aesKey, iv, authTag);

  // Log da mensagem descriptografada
  console.log('🔓 Mensagem recebida:', plaintext);

  return plaintext;
}

/* ===================== EXPORTAÇÃO ===================== */

module.exports = {
  processEncryptedPayload
};
