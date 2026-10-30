---
name: crypto-verification
description: Hướng dẫn kỹ thuật và mã mẫu chuẩn thực thi mã hóa AES-256-GCM, băm SHA-256 và ký số RSA/Ed25519 bằng mô-đun node:crypto.
---

# Kỹ Thuật Kiểm Chứng Mật Mã Học (Crypto Verification Skill)

## 1. Tính toán mã băm SHA-256 (File Integrity)
```javascript
import crypto from 'node:crypto';

export function calculateHash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}
```

## 2. Ký số & Xác minh chữ ký (Digital Signature)
```javascript
import crypto from 'node:crypto';

// Ký số dữ liệu bằng Private Key
export function signData(dataBuffer, privateKeyPem) {
  const signer = crypto.createSign('SHA256');
  signer.update(dataBuffer);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}

// Xác minh tính toàn vẹn và nguồn gốc bằng Public Key
export function verifySignature(dataBuffer, signatureBase64, publicKeyPem) {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(dataBuffer);
  verifier.end();
  return verifier.verify(publicKeyPem, signatureBase64, 'base64');
}
```

## 3. Mã hóa & Giải mã lưu trữ AES-256-GCM (Authenticated Encryption)
```javascript
import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Chuẩn GCM

export function encryptBuffer(buffer, secretKey) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, secretKey, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes
  return { iv: iv.toString('hex'), authTag: authTag.toString('hex'), encryptedData: encrypted.toString('base64') };
}

export function decryptBuffer(encryptedBase64, ivHex, authTagHex, secretKey) {
  const decipher = crypto.createDecipheriv(ALGORITHM, secretKey, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedBase64, 'base64')), decipher.final()]);
  return decrypted;
}
```
