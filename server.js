const express = require('express');
const bodyParser = require('body-parser');
const { processEncryptedPayload } = require('./src/js/backend');
const app = express();

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.static('src'));

app.post('/api/receive', (req, res) => {
  try {
    const { encryptedKey, encryptedData, iv, authTag, timestamp, nonce } = req.body;

    // 🧾 Logs temporários
    console.log("📩 Payload recebido:");
    console.log("🔐 Encrypted AES key size:", encryptedKey.length);
    console.log("📦 Encrypted data size:", encryptedData.length);
    console.log("🧩 IV:", iv);
    console.log("🧾 AuthTag:", authTag);
    console.log("🕑 Timestamp:", timestamp);
    console.log("🧠 Nonce:", nonce);

    const plaintext = processEncryptedPayload(req.body);

    console.log("✅ Mensagem descriptografada:", plaintext); // 🟢 Verificação útil

    res.send("🔐 Mensagem descriptografada: " + plaintext);
  } catch (err) {
    console.error("❌ Erro:", err.message);
    res.status(400).send("❌ Erro: " + err.message);
  }
});


app.listen(3000, () => {
  console.log("🚀 Servidor rodando em http://localhost:3000");
});
