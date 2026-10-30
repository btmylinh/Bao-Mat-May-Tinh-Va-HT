import fs from 'node:fs';
import path from 'node:path';
import {
  buildEnvelopeAad,
  calculateHash,
  decryptBuffer,
  decryptEnvelopeBuffer,
  safeCompareHex,
  verifySignature,
} from '../src/crypto/cryptoService.js';
import {
  closeDatabase,
  getDocumentById,
  getUserById,
  getUserByUsername,
  initDatabase,
  listDocuments,
  listKeyInventory,
  syncHashBaselineFile,
} from '../src/db/database.js';

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const STORAGE_DIR = process.env.STORAGE_DIR || path.resolve(process.cwd(), 'storage');
const DB_PATH = process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'vault.db');
const BASELINE_PATH = path.resolve(path.dirname(DB_PATH), 'hash_baseline.txt');
const KEY_INV_CSV_PATH = path.resolve(path.dirname(DB_PATH), 'key_inventory.csv');

const targetFileArg = process.argv[2] ? path.resolve(process.cwd(), process.argv[2]) : null;

function loadBaselineMap() {
  const map = new Map();
  if (!fs.existsSync(BASELINE_PATH)) return map;
  const lines = fs.readFileSync(BASELINE_PATH, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      map.set(parts[1], parts[0]);
    }
  }
  return map;
}

/**
 * Inspect SHA-256 hashes, Baseline Drift (Lab 3), and Hybrid Envelope & Key Inventory (Lab 4).
 */
async function inspectVaultDocuments() {
  console.log('========================================================================');
  console.log(' [SHA-256 & HYBRID ENVELOPE INSPECTOR] DOI CHIEU BASELINE & KEY INVENTORY');
  console.log('========================================================================');

  if (targetFileArg) {
    if (!fs.existsSync(targetFileArg)) {
      console.error(`[ERROR] Khong tim thay tep ben ngoai: ${targetFileArg}`);
      process.exit(1);
    }
    const externalBuf = fs.readFileSync(targetFileArg);
    const externalHash = calculateHash(externalBuf);
    console.log(` -> Tep kiem tra ben ngoai : ${targetFileArg}`);
    console.log(` -> Dung luong             : ${externalBuf.length} bytes`);
    console.log(` -> SHA-256 (node:crypto)  : ${externalHash}`);
    console.log('------------------------------------------------------------------------');
    console.log(' Lenh he dieu hanh tuong duong de doi chieu doc lap:');
    console.log(`   PowerShell : Get-FileHash "${targetFileArg}" -Algorithm SHA256`);
    console.log(`   CMD        : certutil -hashfile "${targetFileArg}" SHA256`);
    console.log('------------------------------------------------------------------------');
  }

  // Try fetching from live server first
  try {
    const res = await fetch(`${BASE_URL}/api/documents`);
    if (res.ok) {
      const { documents } = await res.json();
      const keyRes = await fetch(`${BASE_URL}/api/documents/key-inventory`);
      const keyData = keyRes.ok ? await keyRes.json() : { keys: [] };
      const baselineMap = loadBaselineMap();

      console.log(`\n [KEY INVENTORY] Danh muc khoa KEK (${KEY_INV_CSV_PATH}):`);
      for (const k of keyData.keys || []) {
        console.log(
          `   * ${k.key_id.padEnd(26)} | ${k.algorithm.padEnd(16)} | Status: ${k.status.padEnd(8)} | SPKI SHA-256: ${String(k.fingerprint_sha256_spki).slice(0, 24)}...`
        );
      }

      if (!documents || documents.length === 0) {
        console.log('\n [!] Kho van ban hien dang trong.');
        return;
      }

      for (const doc of documents) {
        const verifyRes = await fetch(`${BASE_URL}/api/documents/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ documentId: doc.id }),
        });
        const verifyData = await verifyRes.json();
        const baselineKey = `${doc.docCode}|${doc.originalFilename}`;
        const baselineHash = baselineMap.get(baselineKey) || doc.sha256Hash;
        const actualHash = verifyData.actualHash || '';
        const baselineMatched =
          actualHash && !actualHash.startsWith('CORRUPTED') && safeCompareHex(actualHash, baselineHash);

        console.log(`\n [VAN BAN] ${doc.docCode} - ${doc.originalFilename} (ID: ${doc.id})`);
        console.log(`   - Pham vi (Visibility)  : ${doc.visibility} (${doc.visibilityLabel})`);
        console.log(`   - Nguoi ky / Don vi     : ${doc.issuerName}`);
        console.log(`   - Envelope KEK Key ID   : ${doc.keyId}`);
        console.log(
          `   - Wrapped DEK (OAEP)    : ${doc.wrappedDekBase64 ? `${doc.wrappedDekBase64.slice(0, 36)}...` : 'Legacy Master Key'}`
        );
        console.log(
          `   - AAD Context Binding   : ${doc.aadBase64 ? Buffer.from(doc.aadBase64, 'base64').toString('utf8') : 'N/A'}`
        );
        console.log(`   - SHA-256 Baseline      : ${baselineHash}`);
        console.log(`   - SHA-256 Thuc te       : ${actualHash || 'KHONG_THE_GIAI_MA (Corrupted)'}`);
        console.log(
          `   - So khop Baseline      : ${baselineMatched ? 'MATCH (Nguyen ven)' : 'MISMATCH (Phat hien Drift / Tampering!)'}`
        );
        console.log(`   - AES-256-GCM IV (12B)  : ${doc.ivHex}`);
        console.log(`   - GCM Auth Tag (16B)    : ${doc.authTagHex}`);
        console.log(
          `   - Ket qua Doi chieu     : ${
            verifyData.verified ? 'HOP LE (MATCH & VALID SIGNATURE)' : `CANH BAO (${verifyData.errorCode})`
          }`
        );
      }
      console.log('========================================================================');
      return;
    }
  } catch {
    // Fallback to direct SQLite + storage inspection when server is offline
  }

  initDatabase(DB_PATH);
  try {
    syncHashBaselineFile();
    const baselineMap = loadBaselineMap();
    const keys = listKeyInventory();

    console.log(`\n [KEY INVENTORY] Danh muc khoa KEK (${KEY_INV_CSV_PATH}):`);
    for (const k of keys) {
      console.log(
        `   * ${k.key_id.padEnd(26)} | ${k.algorithm.padEnd(16)} | Status: ${k.status.padEnd(8)} | SPKI SHA-256: ${String(k.fingerprint_sha256_spki).slice(0, 24)}...`
      );
    }

    const docs = listDocuments();
    if (!docs || docs.length === 0) {
      console.log('\n [!] Chua co van ban nao trong SQLite (data/vault.db).');
      return;
    }

    for (let idx = 0; idx < docs.length; idx += 1) {
      const row = docs[idx];
      const doc = getDocumentById(row.id);
      const docCode = `VB-2026-${String(docs.length - idx).padStart(4, '0')}`;
      const encPath = path.join(STORAGE_DIR, doc.storage_filename);
      let actualPlainHash = 'MISSING_STORAGE_FILE';
      let aesOk = false;
      let shaMatch = false;
      let rsaValid = false;

      if (fs.existsSync(encPath)) {
        const encBuf = fs.readFileSync(encPath);
        try {
          const issuer = getUserById(doc.issuer_id) || getUserByUsername('issuer_admin');
          let plainBuf;
          if (doc.wrapped_dek_b64 && issuer && issuer.private_key_pem) {
            const expectedAad = Buffer.from(
              buildEnvelopeAad({
                docId: doc.id,
                issuerId: doc.issuer_id,
                originalFilename: doc.original_filename,
              }),
              'utf8'
            ).toString('base64');
            plainBuf = decryptEnvelopeBuffer({
              encryptedBuffer: encBuf,
              ivHex: doc.iv_hex,
              authTagHex: doc.auth_tag_hex,
              wrappedDekBase64: doc.wrapped_dek_b64,
              issuerPrivateKeyPem: issuer.private_key_pem,
              aadBase64: expectedAad,
            });
          } else {
            plainBuf = decryptBuffer(encBuf, doc.iv_hex, doc.auth_tag_hex);
          }
          aesOk = true;
          actualPlainHash = calculateHash(plainBuf);
          shaMatch = safeCompareHex(actualPlainHash, doc.sha256_hash);
          rsaValid = verifySignature(plainBuf, doc.signature, doc.issuer_public_key_pem);
        } catch {
          aesOk = false;
          actualPlainHash = `CORRUPTED_CIPHERTEXT:${calculateHash(encBuf).slice(0, 32)}`;
        }
      }

      const baselineKey = `${docCode}|${doc.original_filename}`;
      const baselineHash = baselineMap.get(baselineKey) || doc.sha256_hash;

      console.log(`\n [VAN BAN] ${docCode} - ${doc.original_filename} (ID: ${doc.id})`);
      console.log(`   - Pham vi (Visibility)  : ${doc.visibility || 'PUBLIC'}`);
      console.log(`   - Nguoi ky / Don vi     : ${doc.issuer_name}`);
      console.log(`   - Envelope KEK Key ID   : ${doc.key_id || 'vault-rsa-prod-2026Q4'}`);
      console.log(`   - SHA-256 Baseline      : ${baselineHash}`);
      console.log(`   - SHA-256 Sau giai ma   : ${actualPlainHash}`);
      console.log(`   - So khop Baseline      : ${shaMatch ? 'MATCH' : 'MISMATCH'}`);
      console.log(`   - AES-256-GCM + AAD     : ${aesOk ? 'PASS' : 'FAIL (AUTH_TAG_OR_AAD_MISMATCH)'}`);
      console.log(`   - RSA-PSS Signature     : ${rsaValid ? 'VALID' : 'FORGED / INVALID'}`);
    }
    console.log('========================================================================');
  } finally {
    closeDatabase();
  }
}

await inspectVaultDocuments();
