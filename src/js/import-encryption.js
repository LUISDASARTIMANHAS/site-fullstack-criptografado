// Script.js
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function sendEncrypted() {
  const publicKeyPem = await fetch("/keys/public.pem").then((res) =>
    res.text()
  );

  const aesKeyRaw = crypto.getRandomValues(new Uint8Array(32)); // 256 bits
  const ivRaw = crypto.getRandomValues(new Uint8Array(12)); // GCM recomenda 96 bits

  const aesKey = await crypto.subtle.importKey(
    "raw",
    aesKeyRaw,
    "AES-GCM",
    false,
    ["encrypt"]
  );

  const message = document.getElementById("msg").value;
  const encoder = new TextEncoder();
  const encodedMessage = encoder.encode(message);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivRaw },
    aesKey,
    encodedMessage
  );

  const encryptedArray = new Uint8Array(encryptedBuffer);
  const authTag = encryptedArray.slice(-16); // GCM tag (últimos 16 bytes)
  const encryptedOnly = encryptedArray.slice(0, -16);

  const rsaKey = await importRSAPublicKey(publicKeyPem);
  const encryptedKeyBuffer = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    rsaKey,
    aesKeyRaw
  );

  const payload = {
    encryptedData: bufferToBase64(encryptedOnly),
    encryptedKey: bufferToBase64(encryptedKeyBuffer),
    iv: bufferToBase64(ivRaw),
    authTag: bufferToBase64(authTag),
    timestamp: Date.now(),
    nonce: crypto.getRandomValues(new Uint32Array(1))[0].toString(),
  };

  const res = await fetch("/api/receive", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  document.getElementById("response").innerText = await res.text();
}

async function importRSAPublicKey(pem) {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const b64 = pem
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s/g, "");
  const binaryDer = atob(b64);
  const bytes = new Uint8Array([...binaryDer].map((c) => c.charCodeAt(0)));

  return crypto.subtle.importKey(
    "spki",
    bytes.buffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
