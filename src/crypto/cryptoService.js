import crypto from 'node:crypto';

const AES_ALGORITHM = 'aes-256-gcm';
const IV_BYTE_LENGTH = 12;
const AUTH_TAG_BYTE_LENGTH = 16;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Compute SHA-256 hash of a Buffer or string, returning a 64-character hex string.
 * @param {Buffer|string} buffer
 * @returns {string}
 */
export function calculateHash(buffer) {
  const data = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer));
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Constant-time comparison of two hexadecimal strings using crypto.timingSafeEqual.
 * Prevents timing side-channel attacks.
 * @param {string} hexA
 * @param {string} hexB
 * @returns {boolean}
 */
export function safeCompareHex(hexA, hexB) {
  if (typeof hexA !== 'string' || typeof hexB !== 'string') {
    return false;
  }
  const cleanA = hexA.trim().toLowerCase();
  const cleanB = hexB.trim().toLowerCase();
  if (cleanA.length === 0 || cleanA.length !== cleanB.length || cleanA.length % 2 !== 0) {
    return false;
  }
  if (!/^[0-9a-f]+$/.test(cleanA) || !/^[0-9a-f]+$/.test(cleanB)) {
    return false;
  }
  const bufA = Buffer.from(cleanA, 'hex');
  const bufB = Buffer.from(cleanB, 'hex');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Constant-time comparison of two UTF-8 strings using crypto.timingSafeEqual.
 * @param {string} strA
 * @param {string} strB
 * @returns {boolean}
 */
export function safeCompareStrings(strA, strB) {
  if (typeof strA !== 'string' || typeof strB !== 'string') {
    return false;
  }
  const bufA = Buffer.from(strA, 'utf8');
  const bufB = Buffer.from(strB, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generate an RSA-2048 key pair in PEM format (SPKI for public, PKCS8 for private).
 * @returns {{ publicKeyPem: string, privateKeyPem: string }}
 */
export function generateRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

/**
 * Compute a concise human-readable SHA-256 fingerprint for a Public Key PEM.
 * @param {string} publicKeyPem
 * @returns {string}
 */
export function getPublicKeyFingerprint(publicKeyPem) {
  const hashHex = calculateHash(Buffer.from(String(publicKeyPem).trim(), 'utf8')).toUpperCase();
  return `RSA2048:${hashHex.slice(0, 16)}`;
}

/**
 * Compute standard 64-char hex SHA-256 fingerprint of DER-encoded SubjectPublicKeyInfo (SPKI).
 * Matches Lab 4 (`key_inventory.csv` -> `fingerprint_sha256_spki`).
 * @param {string} publicKeyPem
 * @returns {string}
 */
export function getSpkiSha256Fingerprint(publicKeyPem) {
  try {
    const pubKeyObj = crypto.createPublicKey(publicKeyPem);
    const spkiDer = pubKeyObj.export({ type: 'spki', format: 'der' });
    return calculateHash(spkiDer);
  } catch {
    return calculateHash(Buffer.from(String(publicKeyPem || '').trim(), 'utf8'));
  }
}

/**
 * Build canonical Additional Authenticated Data (AAD) context string for a document envelope.
 * Binds ciphertext to its specific document record to prevent context-swapping attacks.
 * @param {{ docId: string, issuerId: number|string, originalFilename: string }} ctx
 * @returns {string}
 */
export function buildEnvelopeAad({ docId, issuerId, originalFilename }) {
  return `zt-vault-v2|${String(docId || '')}|${String(issuerId ?? '')}|${String(originalFilename || '')}`;
}

/**
 * Wrap a 32-byte DEK (Data Encryption Key) using KEK Public Key with RSA-OAEP-SHA256.
 * @param {Buffer} dekBuffer
 * @param {string} publicKeyPem
 * @returns {string} Base64-encoded wrapped DEK
 */
export function wrapDekRsaOaep(dekBuffer, publicKeyPem) {
  const wrapped = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    dekBuffer
  );
  return wrapped.toString('base64');
}

/**
 * Unwrap a Base64-encoded wrapped DEK using KEK Private Key with RSA-OAEP-SHA256.
 * @param {string} wrappedDekBase64
 * @param {string} privateKeyPem
 * @returns {Buffer} 32-byte DEK Buffer
 */
export function unwrapDekRsaOaep(wrappedDekBase64, privateKeyPem) {
  try {
    const encryptedDek = Buffer.from(String(wrappedDekBase64 || ''), 'base64');
    return crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedDek
    );
  } catch (err) {
    const wrapped = new Error(`RSA-OAEP-SHA256 DEK Unwrap Failed: ${err.message}`);
    wrapped.code = 'DEK_UNWRAP_FAILED';
    throw wrapped;
  }
}

/**
 * Hybrid Envelope Encryption (Lab 4):
 * 1. Generate a fresh random 32-byte DEK and 12-byte IV
 * 2. Bind context via AAD (`cipher.setAAD`)
 * 3. Encrypt payload with AES-256-GCM using DEK
 * 4. Wrap DEK with KEK Public Key using RSA-OAEP-SHA256
 * @param {Buffer|string} plainBuffer
 * @param {string} kekPublicKeyPem
 * @param {string} [aadString='']
 * @returns {{ ivHex: string, authTagHex: string, encryptedBuffer: Buffer, wrappedDekBase64: string, aadBase64: string }}
 */
export function encryptEnvelopeBuffer(plainBuffer, kekPublicKeyPem, aadString = '') {
  const data = Buffer.isBuffer(plainBuffer) ? plainBuffer : Buffer.from(String(plainBuffer));
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(IV_BYTE_LENGTH);
  const aadBuf = Buffer.from(String(aadString || ''), 'utf8');

  const cipher = crypto.createCipheriv(AES_ALGORITHM, dek, iv, {
    authTagLength: AUTH_TAG_BYTE_LENGTH,
  });
  if (aadBuf.length > 0) {
    cipher.setAAD(aadBuf);
  }

  const encryptedBuffer = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const wrappedDekBase64 = wrapDekRsaOaep(dek, kekPublicKeyPem);

  return {
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    encryptedBuffer,
    wrappedDekBase64,
    aadBase64: aadBuf.toString('base64'),
  };
}

/**
 * Hybrid Envelope Decryption (Lab 4):
 * 1. Unwrap 32-byte DEK using KEK Private Key (RSA-OAEP-SHA256)
 * 2. Bind expected AAD context (`decipher.setAAD`)
 * 3. Verify 16-byte AES-256-GCM Auth Tag and decrypt payload
 * @param {object} params
 * @param {Buffer|string} params.encryptedInput
 * @param {string} params.ivHex
 * @param {string} params.authTagHex
 * @param {string} [params.wrappedDekBase64]
 * @param {string} [params.kekPrivateKeyPem]
 * @param {string} [params.expectedAadString='']
 * @param {string} [params.storedAadBase64='']
 * @returns {Buffer}
 */
export function decryptEnvelopeBuffer({
  encryptedInput,
  ivHex,
  authTagHex,
  wrappedDekBase64,
  kekPrivateKeyPem,
  expectedAadString = '',
  storedAadBase64 = '',
}) {
  if (!wrappedDekBase64 || !kekPrivateKeyPem) {
    return decryptBuffer(encryptedInput, ivHex, authTagHex);
  }

  const dek = unwrapDekRsaOaep(wrappedDekBase64, kekPrivateKeyPem);
  const iv = Buffer.from(String(ivHex || ''), 'hex');
  const authTag = Buffer.from(String(authTagHex || ''), 'hex');

  if (iv.length !== IV_BYTE_LENGTH || authTag.length !== AUTH_TAG_BYTE_LENGTH) {
    const err = new Error('Invalid AES-GCM IV or Auth Tag length');
    err.code = 'AUTH_TAG_MISMATCH';
    throw err;
  }

  const ciphertext = Buffer.isBuffer(encryptedInput)
    ? encryptedInput
    : Buffer.from(String(encryptedInput), 'base64');

  const expectedAadBuf = Buffer.from(String(expectedAadString || ''), 'utf8');
  if (storedAadBase64) {
    const storedAadBuf = Buffer.from(String(storedAadBase64), 'base64');
    if (
      expectedAadBuf.length > 0 &&
      (storedAadBuf.length !== expectedAadBuf.length ||
        !crypto.timingSafeEqual(storedAadBuf, expectedAadBuf))
    ) {
      const err = new Error(
        'AAD Context Mismatch: Envelope metadata does not match expected document context'
      );
      err.code = 'AAD_CONTEXT_MISMATCH';
      throw err;
    }
  }

  try {
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, dek, iv, {
      authTagLength: AUTH_TAG_BYTE_LENGTH,
    });
    if (expectedAadBuf.length > 0) {
      decipher.setAAD(expectedAadBuf);
    }
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    const wrapped = new Error(
      `AES-256-GCM Envelope Decryption / AAD Verification Failed: ${err.message}`
    );
    wrapped.code = err.code === 'AAD_CONTEXT_MISMATCH' ? 'AAD_CONTEXT_MISMATCH' : 'AUTH_TAG_MISMATCH';
    throw wrapped;
  }
}

/**
 * Sign binary data using RSA-PSS (SHA-256) and return a Base64-encoded signature.
 * @param {Buffer|string} dataBuffer
 * @param {string} privateKeyPem
 * @returns {string}
 */
export function signData(dataBuffer, privateKeyPem) {
  const data = Buffer.isBuffer(dataBuffer) ? dataBuffer : Buffer.from(String(dataBuffer));
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  signer.end();
  return signer.sign(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    },
    'base64'
  );
}

/**
 * Verify an RSA-PSS (or legacy PKCS#1 v1.5) SHA-256 signature against binary data and a Public Key PEM.
 * Never throws on malformed input; returns false if verification fails.
 * @param {Buffer|string} dataBuffer
 * @param {string} signatureBase64
 * @param {string} publicKeyPem
 * @returns {boolean}
 */
export function verifySignature(dataBuffer, signatureBase64, publicKeyPem) {
  try {
    if (!signatureBase64 || typeof signatureBase64 !== 'string' || !publicKeyPem) {
      return false;
    }
    const data = Buffer.isBuffer(dataBuffer) ? dataBuffer : Buffer.from(String(dataBuffer));
    const pssVerifier = crypto.createVerify('SHA256');
    pssVerifier.update(data);
    pssVerifier.end();
    const pssOk = pssVerifier.verify(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      },
      signatureBase64,
      'base64'
    );
    if (pssOk) {
      return true;
    }

    const legacyVerifier = crypto.createVerify('SHA256');
    legacyVerifier.update(data);
    legacyVerifier.end();
    return legacyVerifier.verify(publicKeyPem, signatureBase64, 'base64');
  } catch {
    return false;
  }
}

/**
 * Normalize or derive a 32-byte Master Key Buffer for AES-256-GCM.
 * @param {Buffer|string} [masterKeyInput]
 * @returns {Buffer}
 */
export function resolveMasterKey(masterKeyInput) {
  const raw = masterKeyInput || process.env.STORAGE_MASTER_KEY_HEX || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  if (Buffer.isBuffer(raw)) {
    if (raw.length === 32) {
      return raw;
    }
    return crypto.createHash('sha256').update(raw).digest();
  }
  const str = String(raw).trim();
  if (/^[0-9a-fA-F]{64}$/.test(str)) {
    return Buffer.from(str, 'hex');
  }
  return crypto.createHash('sha256').update(str, 'utf8').digest();
}

/**
 * Encrypt a Buffer using AES-256-GCM with a freshly generated 12-byte random IV.
 * @param {Buffer} buffer
 * @param {Buffer|string} [masterKeyBuffer]
 * @returns {{ ivHex: string, authTagHex: string, encryptedBuffer: Buffer }}
 */
export function encryptBuffer(buffer, masterKeyBuffer) {
  const data = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer));
  const key = resolveMasterKey(masterKeyBuffer);
  const iv = crypto.randomBytes(IV_BYTE_LENGTH);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTE_LENGTH,
  });
  const encryptedBuffer = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    encryptedBuffer,
  };
}

/**
 * Decrypt an AES-256-GCM encrypted Buffer and verify its 16-byte Authentication Tag.
 * Throws an Error with code = 'AUTH_TAG_MISMATCH' if any bit of ciphertext, IV, or authTag was modified.
 * @param {Buffer|string} encryptedInput
 * @param {string} ivHex
 * @param {string} authTagHex
 * @param {Buffer|string} [masterKeyBuffer]
 * @returns {Buffer}
 */
export function decryptBuffer(encryptedInput, ivHex, authTagHex, masterKeyBuffer) {
  try {
    const key = resolveMasterKey(masterKeyBuffer);
    const iv = Buffer.from(String(ivHex || ''), 'hex');
    const authTag = Buffer.from(String(authTagHex || ''), 'hex');

    if (iv.length !== IV_BYTE_LENGTH) {
      const err = new Error(`Invalid AES-GCM IV length: expected ${IV_BYTE_LENGTH} bytes, got ${iv.length}`);
      err.code = 'AUTH_TAG_MISMATCH';
      throw err;
    }
    if (authTag.length !== AUTH_TAG_BYTE_LENGTH) {
      const err = new Error(`Invalid AES-GCM Auth Tag length: expected ${AUTH_TAG_BYTE_LENGTH} bytes, got ${authTag.length}`);
      err.code = 'AUTH_TAG_MISMATCH';
      throw err;
    }

    const ciphertext = Buffer.isBuffer(encryptedInput)
      ? encryptedInput
      : Buffer.from(String(encryptedInput), 'base64');

    const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_BYTE_LENGTH,
    });
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    const wrapped = new Error(
      `AES-256-GCM Decryption / Integrity Verification Failed: ${err.message || 'Authentication tag mismatch'}`
    );
    wrapped.code = 'AUTH_TAG_MISMATCH';
    wrapped.cause = err;
    throw wrapped;
  }
}

/**
 * Create a copy of a Buffer and flip bits at the specified byte index (`^ 0xFF`).
 * Used to simulate a 1-byte tampering attack.
 * @param {Buffer} buffer
 * @param {number} [byteIndex=0]
 * @returns {Buffer}
 */
export function tamperBuffer(buffer, byteIndex = 0) {
  const source = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer));
  if (source.length === 0) {
    return Buffer.from([0xff]);
  }
  const tampered = Buffer.from(source);
  const idx = Math.max(0, Math.min(tampered.length - 1, Number(byteIndex) || 0));
  tampered[idx] = tampered[idx] ^ 0xff;
  return tampered;
}

/**
 * Encode a Buffer into a Base32 string (RFC 4648).
 * @param {Buffer} buffer
 * @returns {string}
 */
export function encodeBase32(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i += 1) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Decode a Base32 string (RFC 4648) into a Buffer.
 * @param {string} base32Str
 * @returns {Buffer}
 */
export function decodeBase32(base32Str) {
  const clean = String(base32Str || '')
    .toUpperCase()
    .replace(/=+$/, '')
    .replace(/[\s-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < clean.length; i += 1) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: ${clean[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Generate a random 160-bit (20-byte) TOTP secret in Base32 format.
 * @returns {string}
 */
export function generateTotpSecret() {
  return encodeBase32(crypto.randomBytes(20));
}

/**
 * Compute a 6-digit RFC 6238 TOTP code (HMAC-SHA1, 30-second step).
 * @param {string} secretBase32
 * @param {number} [timestampMs=Date.now()]
 * @param {number} [stepSeconds=30]
 * @returns {string}
 */
export function generateTotpCode(secretBase32, timestampMs = Date.now(), stepSeconds = 30) {
  const key = decodeBase32(secretBase32);
  const counter = Math.floor(Math.floor(timestampMs / 1000) / stepSeconds);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binaryCode % 1_000_000;
  return String(otp).padStart(6, '0');
}

/**
 * Verify a 6-digit RFC 6238 TOTP code using timingSafeEqual across the allowed window.
 * @param {string} secretBase32
 * @param {string} inputCode
 * @param {number} [timestampMs=Date.now()]
 * @param {number} [window=1]
 * @returns {boolean}
 */
export function verifyTotpCode(secretBase32, inputCode, timestampMs = Date.now(), window = 1) {
  if (typeof inputCode !== 'string' && typeof inputCode !== 'number') {
    return false;
  }
  const normalizedInput = String(inputCode).trim();
  if (!/^\d{6}$/.test(normalizedInput)) {
    return false;
  }
  const stepMs = 30 * 1000;
  let matched = false;
  for (let offset = -window; offset <= window; offset += 1) {
    const candidate = generateTotpCode(secretBase32, timestampMs + offset * stepMs);
    if (safeCompareStrings(candidate, normalizedInput)) {
      matched = true;
    }
  }
  return matched;
}
