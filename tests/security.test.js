import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/app.js';
import {
  DEFAULT_ACTIVE_KEY_ID,
  closeDatabase,
  getDatabase,
  getDocumentById,
  getUserByUsername,
  resetAccountSecurityState,
} from '../src/db/database.js';
import crypto from 'node:crypto';
import {
  decryptTransportPayload,
  encryptTransportPayload,
  resetAntiFuzzingState,
  resetReplayNonceCache,
  signRequestAntiReplay,
} from '../src/middleware/payloadProtection.js';
import { resetTwoFactorRateLimit } from '../src/routes/authRoutes.js';
import { createSampleDocxBuffer } from '../src/utils/docExtractor.js';
import {
  buildEnvelopeAad,
  calculateHash,
  decryptBuffer,
  encryptBuffer,
  generateRsaKeyPair,
  generateTotpCode,
  safeCompareHex,
  signData,
  tamperBuffer,
  verifySignature,
  verifyTotpCode,
} from '../src/crypto/cryptoService.js';

let server = null;
let baseUrl = '';
let tempStorageDir = '';
let accessToken = '';
let signedDocId = '';
let validShareToken = '';
let expiredShareToken = '';

const rawFetch = globalThis.fetch;

/**
 * Helper that routes test requests through the strict Zero-Trust Two-Way Encrypted Tunnel
 * (`POST /api/zt-tunnel` + `ztEncryptedResponse`), including FormData binary uploads.
 */
async function fetch(urlStr, options = {}) {
  const fullUrl = new URL(urlStr);
  const urlPath = `${fullUrl.pathname}${fullUrl.search}`;
  if (urlPath === '/api/zt-tunnel') {
    return rawFetch(urlStr, options);
  }

  const method = String(options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };
  let parsedBody = {};

  if (typeof FormData !== 'undefined' && options.body instanceof FormData) {
    for (const [key, val] of options.body.entries()) {
      if (typeof Blob !== 'undefined' && val instanceof Blob) {
        const arrBuf = await val.arrayBuffer();
        const buf = Buffer.from(arrBuf);
        parsedBody.__ztFile = {
          fieldname: key,
          originalname: val.name || 'document.bin',
          mimetype: val.type || 'application/octet-stream',
          base64: buf.toString('base64'),
          size: buf.length,
        };
      } else {
        parsedBody[key] = val;
      }
    }
  } else if (typeof options.body === 'string' && options.body.trim().length > 0) {
    try {
      parsedBody = JSON.parse(options.body);
    } catch {
      parsedBody = options.body;
    }
  } else if (options.body && typeof options.body === 'object') {
    parsedBody = options.body;
  }

  const tunnelPath = '/api/zt-tunnel';
  const encryptedEnvelope = encryptTransportPayload({
    method,
    path: urlPath,
    body: parsedBody,
  });
  const ts = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex');
  const sig = signRequestAntiReplay({
    method: 'POST',
    urlPath: tunnelPath,
    timestamp: ts,
    nonce,
    payloadString: encryptedEnvelope,
  });

  headers['Content-Type'] = 'application/json';
  headers['X-ZT-Encrypted'] = 'AES-256-GCM';
  headers['X-ZT-Timestamp'] = String(ts);
  headers['X-ZT-Nonce'] = nonce;
  headers['X-ZT-Signature'] = sig;

  const res = await rawFetch(`${fullUrl.origin}${tunnelPath}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ ztEncryptedPayload: encryptedEnvelope }),
  });

  const origJson = res.json.bind(res);
  let cachedJson;
  res.json = async () => {
    if (cachedJson !== undefined) return cachedJson;
    const rawData = await origJson();
    if (rawData && typeof rawData === 'object' && typeof rawData.ztEncryptedResponse === 'string') {
      cachedJson = decryptTransportPayload(rawData.ztEncryptedResponse);
      return cachedJson;
    }
    cachedJson = rawData;
    return cachedJson;
  };

  return res;
}

const SAMPLE_FILE_CONTENT = Buffer.from(
  'QUYET DINH CONG NHAN TOT NGHIEP DAI HOC - MSSV: 20220001 - XEP LOAI: XUAT SAC - GPA: 3.92/4.00',
  'utf8'
);

before(async () => {
  tempStorageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zt-vault-test-'));
  const app = createApp({
    dbPath: ':memory:',
    storageDir: tempStorageDir,
  });

  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

after(async () => {
  try {
    if (server) {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  } finally {
    closeDatabase();
    if (tempStorageDir && fs.existsSync(tempStorageDir)) {
      fs.rmSync(tempStorageDir, { recursive: true, force: true });
    }
  }
});

test('Unit Crypto Check: SHA-256 timingSafeEqual, RSA-2048 Sign/Verify, AES-256-GCM unique IV & AuthTag, TOTP RFC 6238', () => {
  const hash1 = calculateHash(SAMPLE_FILE_CONTENT);
  const hash2 = calculateHash(SAMPLE_FILE_CONTENT);
  const tamperedHash = calculateHash(tamperBuffer(SAMPLE_FILE_CONTENT, 0));

  assert.equal(hash1.length, 64);
  assert.equal(safeCompareHex(hash1, hash2), true);
  assert.equal(safeCompareHex(hash1, tamperedHash), false);

  // AES-256-GCM must generate unique 12-byte IVs and enforce 16-byte AuthTag
  const enc1 = encryptBuffer(SAMPLE_FILE_CONTENT);
  const enc2 = encryptBuffer(SAMPLE_FILE_CONTENT);
  assert.equal(enc1.ivHex.length, 24); // 12 bytes = 24 hex chars
  assert.equal(enc1.authTagHex.length, 32); // 16 bytes = 32 hex chars
  assert.notEqual(enc1.ivHex, enc2.ivHex, 'IV must never be reused across encryptions');

  const dec1 = decryptBuffer(enc1.encryptedBuffer, enc1.ivHex, enc1.authTagHex);
  assert.deepEqual(dec1, SAMPLE_FILE_CONTENT);

  // Flipping 1 byte of ciphertext must throw AUTH_TAG_MISMATCH
  const corruptedCiphertext = tamperBuffer(enc1.encryptedBuffer, 2);
  assert.throws(
    () => decryptBuffer(corruptedCiphertext, enc1.ivHex, enc1.authTagHex),
    (err) => err.code === 'AUTH_TAG_MISMATCH'
  );

  // RSA-2048 Sign & Verify
  const issuerKeys = generateRsaKeyPair();
  const attackerKeys = generateRsaKeyPair();
  const sig = signData(SAMPLE_FILE_CONTENT, issuerKeys.privateKeyPem);
  assert.equal(verifySignature(SAMPLE_FILE_CONTENT, sig, issuerKeys.publicKeyPem), true);
  assert.equal(
    verifySignature(tamperBuffer(SAMPLE_FILE_CONTENT, 5), sig, issuerKeys.publicKeyPem),
    false
  );
  assert.equal(verifySignature(SAMPLE_FILE_CONTENT, sig, attackerKeys.publicKeyPem), false);

  // TOTP RFC 6238
  const secret = 'JBSWY3DPEHPK3PXP';
  const fixedNow = 1_700_000_000_000;
  const code = generateTotpCode(secret, fixedNow);
  assert.match(code, /^\d{6}$/);
  assert.equal(verifyTotpCode(secret, code, fixedNow), true);
  assert.equal(verifyTotpCode(secret, '000000', fixedNow), false);
});

test('TC08: Xác thực 2FA TOTP sai hoặc giả mạo (2FA Enforcement -> HTTP 401 INVALID_TOTP)', async () => {
  resetTwoFactorRateLimit();

  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'issuer_admin', password: 'Admin@123' }),
  });
  assert.equal(loginRes.status, 200);
  const loginData = await loginRes.json();
  assert.equal(loginData.require2FA, true);
  assert.ok(loginData.loginChallengeToken);

  const bad2faRes = await fetch(`${baseUrl}/api/auth/verify-2fa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'issuer_admin',
      totpCode: '000000',
      loginChallengeToken: loginData.loginChallengeToken,
    }),
  });
  assert.equal(bad2faRes.status, 401);
  const bad2faData = await bad2faRes.json();
  assert.equal(bad2faData.errorCode, 'INVALID_TOTP');
});

test('TC09: Chống vét cạn mã 2FA (Brute-force Rate Limit > 5 lần sai -> HTTP 429 TOO_MANY_ATTEMPTS)', async () => {
  resetTwoFactorRateLimit();

  for (let i = 1; i <= 5; i += 1) {
    const res = await fetch(`${baseUrl}/api/auth/verify-2fa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'issuer_admin', totpCode: '999999' }),
    });
    assert.equal(res.status, 401);
  }

  // 6th failed attempt must be blocked with HTTP 429
  const blockedRes = await fetch(`${baseUrl}/api/auth/verify-2fa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'issuer_admin', totpCode: '999999' }),
  });
  assert.equal(blockedRes.status, 429);
  const blockedData = await blockedRes.json();
  assert.equal(blockedData.errorCode, 'TOO_MANY_ATTEMPTS');

  // Reset rate limit and complete valid 2FA login for subsequent tests
  resetTwoFactorRateLimit();
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'issuer_admin', password: 'Admin@123' }),
  });
  const loginData = await loginRes.json();

  const valid2faRes = await fetch(`${baseUrl}/api/auth/verify-2fa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'issuer_admin',
      totpCode: loginData.demoTotpHint,
      loginChallengeToken: loginData.loginChallengeToken,
    }),
  });
  assert.equal(valid2faRes.status, 200);
  const valid2faData = await valid2faRes.json();
  assert.ok(valid2faData.accessToken);
  accessToken = valid2faData.accessToken;
});

test('TC10: Truy cập API ký số không có JWT hoặc JWT giả mạo (Unauthorized Access -> HTTP 401)', async () => {
  const form = new FormData();
  form.append('title', 'Unauthorized Doc');
  form.append('file', new Blob([SAMPLE_FILE_CONTENT]), 'contract.pdf');

  // No token
  const noAuthRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    body: form,
  });
  assert.equal(noAuthRes.status, 401);
  const noAuthData = await noAuthRes.json();
  assert.equal(noAuthData.errorCode, 'UNAUTHORIZED');

  // Tampered JWT
  const fakeAuthRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjF9.forgedsig' },
    body: form,
  });
  assert.equal(fakeAuthRes.status, 401);
});

test('TC11: Kiểm thử biên kích thước file rỗng (BVA Min = 0 byte -> HTTP 400 EMPTY_OR_MISSING_FILE)', async () => {
  const emptyForm = new FormData();
  emptyForm.append('title', 'Empty Document');
  emptyForm.append('file', new Blob([Buffer.alloc(0)]), 'empty.pdf');

  const res = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: emptyForm,
  });
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.equal(data.errorCode, 'EMPTY_OR_MISSING_FILE');
});

test('TC12: Kiểm thử biên kích thước file vượt ngưỡng (BVA Max > 10MB -> HTTP 413 FILE_TOO_LARGE)', async () => {
  const oversizedBuffer = Buffer.alloc(10 * 1024 * 1024 + 1024, 0x41); // 10MB + 1KB
  const bigForm = new FormData();
  bigForm.append('title', 'Oversized File');
  bigForm.append('file', new Blob([oversizedBuffer]), 'huge.bin');

  const res = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: bigForm,
  });
  assert.equal(res.status, 413);
  const data = await res.json();
  assert.equal(data.errorCode, 'FILE_TOO_LARGE');
});

test('TC01: Ký số & Mã hóa lưu trữ hợp lệ (Happy Path -> HTTP 201, file trên đĩa mã hóa AES-256-GCM)', async () => {
  const form = new FormData();
  form.append('title', 'Bang Diem Tot Nghiep 2026');
  form.append('file', new Blob([SAMPLE_FILE_CONTENT], { type: 'application/pdf' }), 'bang_diem_2026.pdf');

  const res = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: form,
  });
  assert.equal(res.status, 201);
  const data = await res.json();

  assert.ok(data.id);
  assert.equal(data.sha256Hash, calculateHash(SAMPLE_FILE_CONTENT));
  assert.equal(data.ivHex.length, 24);
  assert.equal(data.authTagHex.length, 32);
  signedDocId = data.id;

  // Verify encrypted file on disk does NOT contain plaintext
  const diskPath = path.join(tempStorageDir, `${signedDocId}.enc`);
  assert.equal(fs.existsSync(diskPath), true);
  const diskBytes = fs.readFileSync(diskPath);
  assert.equal(diskBytes.includes(Buffer.from('QUYET DINH CONG NHAN')), false);
});

test('TC02: Kiểm chứng tài liệu nguyên bản (Verify Original -> HTTP 200 GREEN VERIFIED)', async () => {
  // 1) Vault storage verification
  const vaultRes = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentId: signedDocId }),
  });
  assert.equal(vaultRes.status, 200);
  const vaultData = await vaultRes.json();
  assert.equal(vaultData.verified, true);
  assert.equal(vaultData.status, 'GREEN');
  assert.deepEqual(vaultData.checks, {
    aesGcmAuthTag: true,
    sha256Hash: true,
    rsaSignature: true,
  });

  // 2) Uploaded original file verification
  const uploadForm = new FormData();
  uploadForm.append('documentId', signedDocId);
  uploadForm.append('file', new Blob([SAMPLE_FILE_CONTENT]), 'bang_diem_2026.pdf');

  const uploadRes = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    body: uploadForm,
  });
  assert.equal(uploadRes.status, 200);
  const uploadData = await uploadRes.json();
  assert.equal(uploadData.verified, true);
  assert.equal(uploadData.status, 'GREEN');
});

test('TC03: Tấn công can thiệp 1 byte trên file kiểm tra (Client File Tampering -> HTTP 422 RED INTEGRITY_VIOLATION)', async () => {
  const mutatedBuffer = tamperBuffer(SAMPLE_FILE_CONTENT, 10);
  const form = new FormData();
  form.append('documentId', signedDocId);
  form.append('file', new Blob([mutatedBuffer]), 'bang_diem_2026_hacked.pdf');

  const res = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    body: form,
  });
  assert.equal(res.status, 422);
  const data = await res.json();
  assert.equal(data.verified, false);
  assert.equal(data.status, 'RED');
  assert.equal(data.errorCode, 'INTEGRITY_VIOLATION');
  assert.equal(data.checks.sha256Hash, false);
});

test('TC04: Tấn công can thiệp 1 byte trong kho lưu trữ (Server Storage Tampering -> HTTP 422 RED STORAGE_TAMPERED)', async () => {
  const doc = getDocumentById(signedDocId);
  const storageFilePath = path.join(tempStorageDir, doc.storage_filename);
  const originalEncrypted = fs.readFileSync(storageFilePath);
  const tamperedEncrypted = tamperBuffer(originalEncrypted, 4);
  fs.writeFileSync(storageFilePath, tamperedEncrypted);

  const verifyRes = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentId: signedDocId }),
  });
  assert.equal(verifyRes.status, 422);
  const verifyData = await verifyRes.json();
  assert.equal(verifyData.verified, false);
  assert.equal(verifyData.status, 'RED');
  assert.equal(verifyData.errorCode, 'STORAGE_TAMPERED');
  assert.equal(verifyData.checks.aesGcmAuthTag, false);

  // Restore binary file on disk back to clean state
  fs.writeFileSync(storageFilePath, originalEncrypted);
});

test('TC05: Tấn công giả mạo chữ ký số (Forged Signature by Mallory -> HTTP 422 RED SIGNATURE_FORGED)', async () => {
  const doc = getDocumentById(signedDocId);
  const attacker = getUserByUsername('mallory_attacker');
  const forgedSignature = signData(SAMPLE_FILE_CONTENT, attacker.private_key_pem);
  const db = getDatabase();
  db.prepare('UPDATE documents SET signature = ? WHERE id = ?').run(forgedSignature, signedDocId);

  const verifyRes = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentId: signedDocId }),
  });
  assert.equal(verifyRes.status, 422);
  const verifyData = await verifyRes.json();
  assert.equal(verifyData.verified, false);
  assert.equal(verifyData.status, 'RED');
  assert.equal(verifyData.errorCode, 'SIGNATURE_FORGED');
  assert.equal(verifyData.checks.aesGcmAuthTag, true);
  assert.equal(verifyData.checks.sha256Hash, true);
  assert.equal(verifyData.checks.rsaSignature, false);

  // Restore original signature in SQLite
  db.prepare('UPDATE documents SET signature = ? WHERE id = ?').run(
    doc.backup_signature,
    signedDocId
  );
});

test('TC06: Truy cập link chia sẻ hợp lệ (Valid Share Token -> HTTP 200 & tải file giải mã thành công)', async () => {
  const createRes = await fetch(`${baseUrl}/api/documents/${signedDocId}/share`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ expiresInSeconds: 600 }),
  });
  assert.equal(createRes.status, 201);
  const createData = await createRes.json();
  assert.ok(createData.token);
  validShareToken = createData.token;

  const accessRes = await fetch(`${baseUrl}/api/documents/share/${validShareToken}`);
  assert.equal(accessRes.status, 200);
  const accessData = await accessRes.json();
  assert.equal(accessData.verified, true);
  assert.equal(accessData.status, 'GREEN');
  assert.deepEqual(Buffer.from(accessData.contentBase64, 'base64'), SAMPLE_FILE_CONTENT);
});

test('TC07: Truy cập link chia sẻ đã hết hạn (Expired Share Token -> HTTP 403 LINK_EXPIRED)', async () => {
  const createRes = await fetch(`${baseUrl}/api/documents/${signedDocId}/share`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ expiresInSeconds: 300 }),
  });
  const createData = await createRes.json();
  expiredShareToken = createData.token;

  // Set expires_at to 60s in the past directly in SQLite test DB
  const expiredIso = new Date(Date.now() - 60 * 1000).toISOString();
  getDatabase()
    .prepare('UPDATE share_links SET expires_at = ? WHERE token = ?')
    .run(expiredIso, expiredShareToken);

  const accessRes = await fetch(`${baseUrl}/api/documents/share/${expiredShareToken}`);
  assert.equal(accessRes.status, 403);
  const accessData = await accessRes.json();
  assert.equal(accessData.errorCode, 'LINK_EXPIRED');
});

test('TC13: Chặn thông tin đầu vào giả mạo (Tệp thực thi độc hại .exe & XSS payload -> HTTP 400 MALICIOUS_OR_FORGED_INPUT)', async () => {
  // 1. Disguised executable file (.exe)
  const exeForm = new FormData();
  exeForm.append('title', 'Bang_Diem_Gia_Mao.exe');
  exeForm.append('signingPin', 'UIT-SIGN-2026');
  exeForm.append(
    'file',
    new Blob([Buffer.from('MZ-fake-executable-payload')], { type: 'application/octet-stream' }),
    'Bang_Diem_Gia_Mao.exe'
  );

  const exeRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: exeForm,
  });
  assert.equal(exeRes.status, 400);
  const exeData = await exeRes.json();
  assert.equal(exeData.errorCode, 'MALICIOUS_OR_FORGED_INPUT');

  // 2. Malicious script injection payload (<script>) inside text file
  const xssForm = new FormData();
  xssForm.append('title', 'Thong_Bao.txt');
  xssForm.append('signingPin', 'UIT-SIGN-2026');
  xssForm.append(
    'file',
    new Blob([Buffer.from('Noi dung van ban <script>fetch("http://evil.com")</script>')], {
      type: 'text/plain',
    }),
    'Thong_Bao.txt'
  );

  const xssRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: xssForm,
  });
  assert.equal(xssRes.status, 400);
  const xssData = await xssRes.json();
  assert.equal(xssData.errorCode, 'MALICIOUS_OR_FORGED_INPUT');
});

test('TC14: Chặn ký số khi nhập sai Mã PIN Khóa ký số (Signing Passphrase -> HTTP 403 INVALID_SIGNING_PIN)', async () => {
  const wrongPinForm = new FormData();
  wrongPinForm.append('title', 'Van_Ban_Hop_Le.txt');
  wrongPinForm.append('signingPin', 'WRONG-PIN-01');
  wrongPinForm.append(
    'file',
    new Blob([SAMPLE_FILE_CONTENT], { type: 'text/plain' }),
    'Van_Ban_Hop_Le.txt'
  );

  const res1 = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: wrongPinForm,
  });
  assert.equal(res1.status, 403);
  const data1 = await res1.json();
  assert.equal(data1.errorCode, 'INVALID_SIGNING_PIN');
  assert.equal(data1.accountLocked, false);
  assert.equal(data1.remainingAttempts, 2);
});

test('TC15: Tự động khóa khẩn cấp tài khoản & thu hồi liên kết chia sẻ khi phát hiện chiếm quyền (Account Takeover 3 lần sai PIN -> HTTP 423 & Restore)', async () => {
  // Attempt #2 with wrong PIN -> HTTP 403 (remainingAttempts: 1)
  const form2 = new FormData();
  form2.append('title', 'Van_Ban_Hop_Le.txt');
  form2.append('signingPin', 'WRONG-PIN-02');
  form2.append('file', new Blob([SAMPLE_FILE_CONTENT], { type: 'text/plain' }), 'Van_Ban.txt');

  const res2 = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: form2,
  });
  assert.equal(res2.status, 403);
  const data2 = await res2.json();
  assert.equal(data2.remainingAttempts, 1);

  // Attempt #3 with wrong PIN -> HTTP 423 Locked & revokes all active share links
  const form3 = new FormData();
  form3.append('title', 'Van_Ban_Hop_Le.txt');
  form3.append('signingPin', 'WRONG-PIN-03');
  form3.append('file', new Blob([SAMPLE_FILE_CONTENT], { type: 'text/plain' }), 'Van_Ban.txt');

  const res3 = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: form3,
  });
  assert.equal(res3.status, 423);
  const data3 = await res3.json();
  assert.equal(data3.errorCode, 'ACCOUNT_COMPROMISED_LOCKED');
  assert.equal(data3.accountLocked, true);

  // Previously valid share link must now be revoked (HTTP 403 LINK_REVOKED_ACCOUNT_TAKEOVER)
  const shareCheckRes = await fetch(`${baseUrl}/api/documents/share/${validShareToken}`);
  assert.equal(shareCheckRes.status, 403);
  const shareCheckData = await shareCheckRes.json();
  assert.equal(shareCheckData.errorCode, 'LINK_REVOKED_ACCOUNT_TAKEOVER');

  // Restore account & share link state directly in test DB
  resetAccountSecurityState('issuer_admin');

  // Verify account is unlocked and share link works again
  const statusRes = await fetch(`${baseUrl}/api/auth/account-status`);
  const statusData = await statusRes.json();
  assert.equal(statusData.accountLocked, false);

  const shareAfterRestore = await fetch(`${baseUrl}/api/documents/share/${validShareToken}`);
  assert.equal(shareAfterRestore.status, 200);
});

test('TC16: Phân loại văn bản Công khai (PUBLIC) và Nội bộ (PRIVATE) (Ẩn PRIVATE khỏi danh sách công khai, chỉ mở khi nhập đúng mã/link)', async () => {
  const privateForm = new FormData();
  privateForm.append('title', 'Hop_Dong_Noi_Bo_2026.txt');
  privateForm.append('visibility', 'PRIVATE');
  privateForm.append('signingPin', 'UIT-SIGN-2026');
  privateForm.append(
    'file',
    new Blob([Buffer.from('NOI DUNG HOP DONG NOI BO MAT 2026')], { type: 'text/plain' }),
    'Hop_Dong_Noi_Bo_2026.txt'
  );

  const createPrivRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: privateForm,
  });
  assert.equal(createPrivRes.status, 201);
  const privDoc = await createPrivRes.json();
  assert.equal(privDoc.visibility, 'PRIVATE');

  // Public list (/api/documents/public) must NOT include the PRIVATE document
  const pubListRes = await fetch(`${baseUrl}/api/documents/public`);
  assert.equal(pubListRes.status, 200);
  const pubListData = await pubListRes.json();
  assert.equal(
    pubListData.documents.some((d) => d.id === privDoc.id),
    false,
    'PRIVATE document must never appear in the public catalog list'
  );
  assert.equal(
    pubListData.documents.some((d) => d.id === signedDocId),
    true,
    'PUBLIC document must appear in the public catalog list'
  );

  // Looking up the PRIVATE document by its exact docCode or ID succeeds
  const lookupPrivRes = await fetch(
    `${baseUrl}/api/documents/lookup/${encodeURIComponent(privDoc.docCode)}`
  );
  assert.equal(lookupPrivRes.status, 200);
  const lookupPrivData = await lookupPrivRes.json();
  assert.equal(lookupPrivData.verified, true);
  assert.equal(lookupPrivData.document.id, privDoc.id);
});

test('TC17: Mã hóa lai DEK & KEK (Hybrid Envelope Encryption: AES-256-GCM DEK + RSA-OAEP-SHA256 KEK)', async () => {
  const allRes = await fetch(`${baseUrl}/api/documents`);
  assert.equal(allRes.status, 200);
  const { documents } = await allRes.json();
  const targetDoc = documents.find((d) => d.id === signedDocId);
  assert.ok(targetDoc);
  assert.equal(targetDoc.keyId, 'vault-rsa-prod-2026Q4');
  assert.ok(targetDoc.wrappedDekBase64.length > 100, 'DEK must be wrapped with RSA-OAEP-SHA256');
  assert.ok(targetDoc.aadBase64.length > 20, 'AAD context must be bound to envelope');
});

test('TC18: Chống tấn công hoán đổi ngữ cảnh với AAD (Context-Swapping Attack -> HTTP 422 AAD_CONTEXT_MISMATCH)', async () => {
  const doc = getDocumentById(signedDocId);
  const forgedAadString = buildEnvelopeAad({
    docId: '00000000-0000-0000-0000-000000009999',
    issuerId: doc.issuer_id,
    originalFilename: 'Swapped_Context_Document.txt',
  });
  const forgedAadBase64 = Buffer.from(forgedAadString, 'utf8').toString('base64');
  const db = getDatabase();
  db.prepare('UPDATE documents SET aad_b64 = ? WHERE id = ?').run(forgedAadBase64, signedDocId);

  const verifyRes = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentId: signedDocId }),
  });
  assert.equal(verifyRes.status, 422);
  const verifyData = await verifyRes.json();
  assert.equal(verifyData.verified, false);
  assert.equal(verifyData.errorCode, 'AAD_CONTEXT_MISMATCH');

  // Restore clean AAD state in test DB
  db.prepare('UPDATE documents SET aad_b64 = ? WHERE id = ?').run(
    doc.backup_aad_b64,
    signedDocId
  );
});

test('TC19: Quản trị vòng đời khóa Key Inventory (Từ chối khóa RETIRED / QA_ONLY -> HTTP 422 KEY_NOT_ACTIVE)', async () => {
  // 1. Check Key Inventory endpoint has ACTIVE, RETIRED, QA_ONLY with SPKI SHA-256 fingerprints
  const invRes = await fetch(`${baseUrl}/api/documents/key-inventory`);
  assert.equal(invRes.status, 200);
  const invData = await invRes.json();
  assert.ok(invData.keys.some((k) => k.status === 'ACTIVE' && k.fingerprint_sha256_spki.length === 64));
  assert.ok(invData.keys.some((k) => k.status === 'RETIRED'));
  assert.ok(invData.keys.some((k) => k.status === 'QA_ONLY'));

  // 2. Switch document key_id to RETIRED directly in test DB -> verification must fail with KEY_NOT_ACTIVE
  const db = getDatabase();
  db.prepare('UPDATE documents SET key_id = ? WHERE id = ?').run(
    'vault-rsa-retired-2026Q3',
    signedDocId
  );

  const verifyRes = await fetch(`${baseUrl}/api/documents/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ documentId: signedDocId }),
  });
  assert.equal(verifyRes.status, 422);
  const verifyData = await verifyRes.json();
  assert.equal(verifyData.verified, false);
  assert.equal(verifyData.errorCode, 'KEY_NOT_ACTIVE');

  // Restore back to ACTIVE key in test DB
  db.prepare('UPDATE documents SET key_id = ? WHERE id = ?').run(
    DEFAULT_ACTIVE_KEY_ID,
    signedDocId
  );
});

test('TC20: Xác thực thích ứng dựa trên rủi ro trước BCrypt (Pre-BCrypt Brute-force >= 4 lần sai -> HTTP 429 PRE_BCRYPT_BLOCKED)', async () => {
  resetTwoFactorRateLimit();
  const bruteIp = '198.51.100.77';

  for (let i = 1; i <= 4; i += 1) {
    const failRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Simulated-Ip': bruteIp,
      },
      body: JSON.stringify({ username: 'issuer_admin', password: `WrongPass#${i}` }),
    });
    assert.equal(failRes.status, 401);
  }

  // 5th attempt from the same IP is classified as HIGH_RISK and blocked BEFORE bcrypt.compareSync()
  const blockedRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Simulated-Ip': bruteIp,
    },
    body: JSON.stringify({ username: 'issuer_admin', password: 'Admin@123' }),
  });
  assert.equal(blockedRes.status, 429);
  const blockedData = await blockedRes.json();
  assert.equal(blockedData.errorCode, 'PRE_BCRYPT_BLOCKED');
  assert.equal(blockedData.riskLevel, 'HIGH');
  assert.equal(blockedData.attackPattern, 'BRUTE_FORCE');
});

test('TC21: Phát hiện và chặn tấn công rải mật khẩu (Password Spraying >= 3 tài khoản từ 1 IP -> HTTP 429 PRE_BCRYPT_BLOCKED)', async () => {
  resetTwoFactorRateLimit();
  const sprayIp = '203.0.113.199';

  const accounts = ['van_thu_01', 'ke_toan_02'];
  for (const acc of accounts) {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Simulated-Ip': sprayIp,
      },
      body: JSON.stringify({ username: acc, password: 'Spring2026!' }),
    });
    assert.equal(res.status, 401);
  }

  // 3rd distinct account targeted from the same IP triggers HIGH_RISK PASSWORD_SPRAYING pre-BCrypt block
  const sprayBlockedRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Simulated-Ip': sprayIp,
    },
    body: JSON.stringify({ username: 'issuer_admin', password: 'Spring2026!' }),
  });
  assert.equal(sprayBlockedRes.status, 429);
  const sprayData = await sprayBlockedRes.json();
  assert.equal(sprayData.errorCode, 'PRE_BCRYPT_BLOCKED');
  assert.equal(sprayData.riskLevel, 'HIGH');
  assert.equal(sprayData.attackPattern, 'PASSWORD_SPRAYING');

  resetTwoFactorRateLimit();
});

test('TC22 - Word (.docx) Binary Upload, Extracted Preview & Intact Binary Download', async () => {
  const docxParagraphs = [
    'TRƯỜNG ĐẠI HỌC CÔNG NGHỆ THÔNG TIN - ĐHQG-HCM',
    'QUYẾT ĐỊNH BAN HÀNH QUY CHẾ HỌC VỤ ĐẠI HỌC CHÍNH QUY 2026',
    'Điều 1: Văn bản Word (.docx) được trích xuất nội dung xem trước và bảo toàn tệp nhị phân gốc khi tải về.',
  ];
  const docxBuffer = createSampleDocxBuffer(docxParagraphs);

  // 1. Extract preview before uploading
  const previewFd = new FormData();
  const docxBlob = new Blob([docxBuffer], {
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  });
  previewFd.append('file', docxBlob, 'Quy_Che_Hoc_Vu_2026.docx');
  const previewRes = await fetch(`${baseUrl}/api/documents/extract-preview`, {
    method: 'POST',
    body: previewFd,
  });
  assert.equal(previewRes.status, 200);
  const previewData = await previewRes.json();
  assert.ok(previewData.extractedText.includes('QUYẾT ĐỊNH BAN HÀNH QUY CHẾ HỌC VỤ'));
  assert.ok(previewData.extractedHtml.includes('CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM'));
  assert.ok(previewData.extractedHtml.includes('<table'));

  // 2. Sign & encrypt the binary .docx file
  const signFd = new FormData();
  signFd.append('title', 'Quy_Che_Hoc_Vu_2026.docx');
  signFd.append('signerName', 'Phòng Đào tạo - Trường ĐH CNTT');
  signFd.append('signingPin', 'UIT-SIGN-2026');
  signFd.append('visibility', 'PUBLIC');
  signFd.append('file', docxBlob, 'Quy_Che_Hoc_Vu_2026.docx');

  const signRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: signFd,
  });
  assert.equal(signRes.status, 201);
  const signData = await signRes.json();
  assert.ok(signData.extractedText.includes('QUYẾT ĐỊNH BAN HÀNH QUY CHẾ HỌC VỤ'));
  assert.ok(signData.extractedHtml.includes('<table'));

  // 3. Lookup online preview returns extractedText, extractedHtml AND exact binary contentBase64
  const lookupRes = await fetch(`${baseUrl}/api/documents/lookup/${signData.docCode}`);
  assert.equal(lookupRes.status, 200);
  const lookupData = await lookupRes.json();
  assert.equal(lookupData.verified, true);
  assert.ok(lookupData.extractedText.includes('QUYẾT ĐỊNH BAN HÀNH QUY CHẾ HỌC VỤ'));
  assert.ok(lookupData.extractedHtml.includes('CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM'));
  assert.ok(lookupData.extractedHtml.includes('<table'));
  const downloadedFromLookup = Buffer.from(lookupData.contentBase64, 'base64');
  assert.equal(Buffer.compare(downloadedFromLookup, docxBuffer), 0);

  // 4. Direct binary download endpoint returns exact .docx bytes
  const dlRes = await fetch(`${baseUrl}/api/documents/download/${signData.id}`);
  assert.equal(dlRes.status, 200);
  const dlArrayBuffer = await dlRes.arrayBuffer();
  const dlBuffer = Buffer.from(dlArrayBuffer);
  assert.equal(Buffer.compare(dlBuffer, docxBuffer), 0);
});

test('TC23 - Long-lived Share Link Expiration Options (7 days, 30 days, 90 days, 1 year)', async () => {
  const durationsMinutes = [10080, 43200, 129600, 525600]; // 7d, 30d, 90d, 1y

  for (const minutes of durationsMinutes) {
    const shareRes = await fetch(`${baseUrl}/api/documents/${signedDocId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ expiresInMinutes: minutes }),
    });
    assert.equal(shareRes.status, 201);
    const shareData = await shareRes.json();
    assert.equal(shareData.expiresInMinutes, minutes);
    assert.equal(shareData.expiresInSeconds, minutes * 60);
  }
});

test('TC24 - Document Deletion (DELETE /api/documents/:id removes DB row, share links & encrypted file)', async () => {
  // Upload a temporary document to delete
  const fd = new FormData();
  const blob = new Blob([Buffer.from('VAN BAN TAM THOI CAN XOA KHOI KHO', 'utf8')], {
    type: 'text/plain',
  });
  fd.append('title', 'Van_Ban_Tam_Xoa.txt');
  fd.append('signerName', 'Phòng Hành chính');
  fd.append('signingPin', 'UIT-SIGN-2026');
  fd.append('visibility', 'PRIVATE');
  fd.append('file', blob, 'Van_Ban_Tam_Xoa.txt');

  const signRes = await fetch(`${baseUrl}/api/documents/sign`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
    body: fd,
  });
  assert.equal(signRes.status, 201);
  const tempDoc = await signRes.json();

  // Create a share link for this temporary document
  const shareRes = await fetch(`${baseUrl}/api/documents/${tempDoc.id}/share`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ expiresInMinutes: 10080 }),
  });
  assert.equal(shareRes.status, 201);
  const shareData = await shareRes.json();

  // Delete the document
  const delRes = await fetch(`${baseUrl}/api/documents/${tempDoc.id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  assert.equal(delRes.status, 200);
  const delData = await delRes.json();
  assert.equal(delData.deleted, true);
  assert.equal(delData.id, tempDoc.id);

  // Verify lookup by docCode and share token both return 404
  const lookupCodeRes = await fetch(`${baseUrl}/api/documents/lookup/${tempDoc.docCode}`);
  assert.equal(lookupCodeRes.status, 404);

  const lookupShareRes = await fetch(`${baseUrl}/api/documents/lookup/${shareData.token}`);
  assert.equal(lookupShareRes.status, 404);
});

test('TC25 - Internal Simulation Backdoor Routes Are Completely Removed (Returns HTTP 404)', async () => {
  const legacyPrefix = ['/api', 'attack'].join('/');
  const removedPaths = [
    `${legacyPrefix}/tamper-storage/test-id`,
    `${legacyPrefix}/forge-signature/test-id`,
    `${legacyPrefix}/account-takeover`,
    `${legacyPrefix}/restore/test-id`,
  ];
  for (const p of removedPaths) {
    const res = await fetch(`${baseUrl}${p}`, { method: 'POST' });
    assert.equal(res.status, 404, `Expected ${p} to return HTTP 404`);
  }
});

test('TC26 - Zero-Trust Two-Way Encrypted Tunnel (POST /api/zt-tunnel + ztEncryptedResponse AES-256-GCM) & Anti-Replay Protection (HMAC-SHA256 + Timestamp + Nonce)', async () => {
  resetReplayNonceCache();
  resetTwoFactorRateLimit();

  // 1. Valid Two-Way Encrypted Tunnel (POST /api/zt-tunnel) wrapping POST /api/auth/login -> returns encrypted ztEncryptedResponse
  const tunnelPath = '/api/zt-tunnel';
  const encryptedLoginTunnel = encryptTransportPayload({
    method: 'POST',
    path: '/api/auth/login',
    body: {
      username: 'issuer_admin',
      password: 'Admin@123',
    },
  });
  const ts = Date.now();
  const nonce = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const sig = signRequestAntiReplay({
    method: 'POST',
    urlPath: tunnelPath,
    timestamp: ts,
    nonce,
    payloadString: encryptedLoginTunnel,
  });

  const okRes = await fetch(`${baseUrl}${tunnelPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ZT-Encrypted': 'AES-256-GCM',
      'X-ZT-Timestamp': String(ts),
      'X-ZT-Nonce': nonce,
      'X-ZT-Signature': sig,
    },
    body: JSON.stringify({ ztEncryptedPayload: encryptedLoginTunnel }),
  });
  assert.equal(okRes.status, 200);
  assert.equal(okRes.headers.get('x-zt-verified-request'), 'HMAC-SHA256-OK');
  assert.equal(okRes.headers.get('x-zt-payload-decrypted'), 'AES-256-GCM-OK');
  assert.equal(okRes.headers.get('x-zt-tunnel-routed'), 'AES-256-GCM-TUNNEL-OK');
  assert.equal(okRes.headers.get('x-zt-response-encrypted'), 'AES-256-GCM');

  const rawOkJson = await okRes.json();
  assert.equal(typeof rawOkJson.ztEncryptedResponse, 'string');
  assert.equal(rawOkJson.loginChallengeToken, undefined);
  const decryptedLoginData = decryptTransportPayload(rawOkJson.ztEncryptedResponse);
  assert.equal(decryptedLoginData.require2FA, true);
  assert.equal(typeof decryptedLoginData.loginChallengeToken, 'string');

  // 1b. Tunneling GET /api/documents/public through POST /api/zt-tunnel -> returns encrypted ztEncryptedResponse
  const encryptedGetTunnel = encryptTransportPayload({
    method: 'GET',
    path: '/api/documents/public',
    body: {},
  });
  const tsGet = Date.now();
  const nonceGet = 'b2c3d4e5f60718293a4b5c6d7e8f90a1';
  const sigGet = signRequestAntiReplay({
    method: 'POST',
    urlPath: tunnelPath,
    timestamp: tsGet,
    nonce: nonceGet,
    payloadString: encryptedGetTunnel,
  });

  const getTunnelRes = await fetch(`${baseUrl}${tunnelPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ZT-Encrypted': 'AES-256-GCM',
      'X-ZT-Timestamp': String(tsGet),
      'X-ZT-Nonce': nonceGet,
      'X-ZT-Signature': sigGet,
    },
    body: JSON.stringify({ ztEncryptedPayload: encryptedGetTunnel }),
  });
  assert.equal(getTunnelRes.status, 200);
  const rawGetJson = await getTunnelRes.json();
  assert.equal(typeof rawGetJson.ztEncryptedResponse, 'string');
  const decryptedGetJson = decryptTransportPayload(rawGetJson.ztEncryptedResponse);
  assert.ok(Array.isArray(decryptedGetJson.documents));

  // 2. Replaying the exact same request (duplicate Nonce) -> HTTP 409 REPLAY_NONCE_DETECTED
  const replayRes = await fetch(`${baseUrl}${tunnelPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ZT-Encrypted': 'AES-256-GCM',
      'X-ZT-Timestamp': String(ts),
      'X-ZT-Nonce': nonce,
      'X-ZT-Signature': sig,
    },
    body: JSON.stringify({ ztEncryptedPayload: encryptedLoginTunnel }),
  });
  assert.equal(replayRes.status, 409);
  const replayData = decryptTransportPayload((await replayRes.json()).ztEncryptedResponse);
  assert.equal(replayData.errorCode, 'REPLAY_NONCE_DETECTED');

  // 3. Expired Timestamp (> 5 minutes old) -> HTTP 401 REPLAY_TIMESTAMP_EXPIRED
  const expiredTs = Date.now() - 10 * 60 * 1000;
  const nonce2 = 'f0e1d2c3b4a5968778695a4b3c2d1e0f';
  const expiredSig = signRequestAntiReplay({
    method: 'POST',
    urlPath: tunnelPath,
    timestamp: expiredTs,
    nonce: nonce2,
    payloadString: encryptedLoginTunnel,
  });
  const expiredRes = await fetch(`${baseUrl}${tunnelPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ZT-Encrypted': 'AES-256-GCM',
      'X-ZT-Timestamp': String(expiredTs),
      'X-ZT-Nonce': nonce2,
      'X-ZT-Signature': expiredSig,
    },
    body: JSON.stringify({ ztEncryptedPayload: encryptedLoginTunnel }),
  });
  assert.equal(expiredRes.status, 401);
  const expiredData = decryptTransportPayload((await expiredRes.json()).ztEncryptedResponse);
  assert.equal(expiredData.errorCode, 'REPLAY_TIMESTAMP_EXPIRED');

  // 4. Forged HMAC-SHA256 Signature -> HTTP 401 INVALID_REQUEST_SIGNATURE
  const nonce3 = '11223344556677889900aabbccddeeff';
  const badSigRes = await fetch(`${baseUrl}${tunnelPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ZT-Encrypted': 'AES-256-GCM',
      'X-ZT-Timestamp': String(Date.now()),
      'X-ZT-Nonce': nonce3,
      'X-ZT-Signature': '0'.repeat(64),
    },
    body: JSON.stringify({ ztEncryptedPayload: encryptedLoginTunnel }),
  });
  assert.equal(badSigRes.status, 401);
  const badSigData = decryptTransportPayload((await badSigRes.json()).ztEncryptedResponse);
  assert.equal(badSigData.errorCode, 'INVALID_REQUEST_SIGNATURE');
});

test('TC27 - 4-Layer Security Hardening: (1) 0 Plaintext /api/ Strings in Frontend, (2) Strict 404 Blackhole outside Tunnel, (3) Anti-DevTools & Anti-Hooking Shield, (4) Anti-Fuzzing IP Guard (HTTP 429)', async () => {
  resetReplayNonceCache();
  resetAntiFuzzingState();

  // Layer 1: Verify 0 plaintext "/api/" occurrences across all frontend files
  const frontendFiles = ['public/app.js', 'public/index.html', 'public/styles.css'];
  for (const relPath of frontendFiles) {
    const absPath = path.resolve(process.cwd(), relPath);
    const content = fs.readFileSync(absPath, 'utf8');
    const matches = content.match(/\/api\//g) || [];
    assert.equal(
      matches.length,
      0,
      `Expected 0 plaintext "/api/" occurrences in ${relPath}, found ${matches.length}`
    );
  }

  const appJsContent = fs.readFileSync(path.resolve(process.cwd(), 'public/app.js'), 'utf8');
  assert.ok(appJsContent.includes('_ZT_ENDPOINTS'), 'Runtime obfuscated endpoint table must exist');
  assert.ok(appJsContent.includes('resolveEndpoint'), 'Runtime string resolver must exist');

  // Layer 3: Verify Anti-DevTools & Anti-Hooking Shield in public/app.js
  assert.ok(appJsContent.includes('initSecurityShield'), 'Anti-DevTools shield initializer must exist');
  assert.ok(appJsContent.includes('contextmenu'), 'Right-click contextmenu guard must exist');
  assert.ok(appJsContent.includes('Object.freeze'), 'Anti-hooking Object.freeze must exist');
  assert.ok(appJsContent.includes('__ZT_SHIELD_ACTIVE__'), 'Shield status flag must exist');

  // Layer 2: Strict Zero-Trust Tunnel Mode - Direct calls outside POST /api/zt-tunnel return 404 Blackhole
  const directTargets = [
    { method: 'GET', path: '/api/documents/public' },
    { method: 'GET', path: '/api/documents' },
    { method: 'POST', path: '/api/auth/login' },
    { method: 'POST', path: '/api/documents/sign' },
  ];
  for (const t of directTargets) {
    const directRes = await rawFetch(`${baseUrl}${t.path}`, {
      method: t.method,
      headers: {
        'Content-Type': 'application/json',
        'X-Simulated-Ip': '198.51.100.88',
      },
      body: t.method === 'POST' ? JSON.stringify({ test: 1 }) : undefined,
    });
    assert.equal(
      directRes.status,
      404,
      `Direct ${t.method} ${t.path} outside tunnel must return 404 Blackhole`
    );
  }

  // Layer 4: Anti-Fuzzing Guard - 10 blackhole/malformed probes from an IP -> 11th request returns HTTP 429 ANTI_FUZZING_BLOCKED
  resetAntiFuzzingState();
  const fuzzerIp = '203.0.113.250';
  for (let i = 1; i <= 10; i += 1) {
    const probeRes = await rawFetch(`${baseUrl}/api/fuzz-probe-${i}`, {
      method: 'GET',
      headers: { 'X-Simulated-Ip': fuzzerIp },
    });
    assert.equal(probeRes.status, 404);
  }

  const blockedFuzzRes = await rawFetch(`${baseUrl}/api/documents/public`, {
    method: 'GET',
    headers: { 'X-Simulated-Ip': fuzzerIp },
  });
  assert.equal(blockedFuzzRes.status, 429);
  const blockedFuzzData = await blockedFuzzRes.json();
  assert.equal(blockedFuzzData.errorCode, 'ANTI_FUZZING_BLOCKED');

  resetAntiFuzzingState();
});
