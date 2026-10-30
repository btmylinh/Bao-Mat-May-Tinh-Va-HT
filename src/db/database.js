import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs';
import {
  generateRsaKeyPair,
  getPublicKeyFingerprint,
  getSpkiSha256Fingerprint,
} from '../crypto/cryptoService.js';

let activeDb = null;
let activeDbPath = null;

export const DEFAULT_ISSUER_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
export const DEFAULT_ISSUER_SIGNING_PIN = 'UIT-SIGN-2026';
export const DEFAULT_ACTIVE_KEY_ID = 'vault-rsa-prod-2026Q4';

function getDataDir() {
  if (activeDbPath && activeDbPath !== ':memory:') {
    return path.dirname(path.resolve(activeDbPath));
  }
  return path.resolve(process.cwd(), 'data');
}

/**
 * Append a single authentication / access event to `data/auth_events.csv` (Lab 3 SOC SHIFT format).
 * Columns: timestamp,user,src_ip,event,asset,details
 * @param {{ timestamp?: string, user: string, srcIp?: string, event: string, asset?: string, details?: string }} row
 */
export function appendAuthEventCsv({
  timestamp = new Date().toISOString(),
  user = 'anonymous',
  srcIp = '127.0.0.1',
  event = 'auth_event',
  asset = 'vault-portal',
  details = '',
}) {
  try {
    const dir = getDataDir();
    fs.mkdirSync(dir, { recursive: true });
    const csvPath = path.join(dir, 'auth_events.csv');
    if (!fs.existsSync(csvPath)) {
      fs.writeFileSync(
        csvPath,
        'timestamp,user,src_ip,event,asset,details\n',
        'utf8'
      );
    }
    const clean = (val) => String(val ?? '').replace(/[\r\n,]+/g, '; ').trim();
    const line = `${clean(timestamp)},${clean(user)},${clean(srcIp)},${clean(event)},${clean(asset)},${clean(details)}\n`;
    fs.appendFileSync(csvPath, line, 'utf8');
  } catch {
    // Ignore filesystem errors in ephemeral environments
  }
}

/**
 * Synchronize `data/key_inventory.csv` with the `key_inventory` SQLite table (Lab 4 format).
 */
export function syncKeyInventoryCsv() {
  try {
    if (!activeDb) return;
    const rows = activeDb
      .prepare('SELECT * FROM key_inventory ORDER BY created_at DESC')
      .all();
    const dir = getDataDir();
    fs.mkdirSync(dir, { recursive: true });
    const csvPath = path.join(dir, 'key_inventory.csv');
    const header =
      'key_id,status,algorithm,key_size_bits,fingerprint_sha256_spki,created_at,notes\n';
    const body = rows
      .map(
        (r) =>
          `${r.key_id},${r.status},${r.algorithm},${r.key_size_bits},${r.fingerprint_sha256_spki},${r.created_at},${String(r.notes || '').replace(/,/g, ';')}`
      )
      .join('\n');
    fs.writeFileSync(csvPath, `${header}${body}\n`, 'utf8');
  } catch {
    // Ignore
  }
}

/**
 * Synchronize `data/hash_baseline.txt` with original registered SHA-256 hashes (Lab 3 & Lab 4 Baseline Drift).
 */
export function syncHashBaselineFile() {
  try {
    if (!activeDb) return;
    const rows = activeDb
      .prepare(
        'SELECT id, original_filename, sha256_hash, key_id, visibility, created_at FROM documents ORDER BY created_at ASC, rowid ASC'
      )
      .all();
    const dir = getDataDir();
    fs.mkdirSync(dir, { recursive: true });
    const baselinePath = path.join(dir, 'hash_baseline.txt');
    const lines = rows.map((r, idx) => {
      const docCode = `VB-2026-${String(idx + 1).padStart(4, '0')}`;
      return `${r.sha256_hash}  ${docCode}  ${r.original_filename}  [key_id=${r.key_id || DEFAULT_ACTIVE_KEY_ID}]  [visibility=${r.visibility || 'PUBLIC'}]`;
    });
    fs.writeFileSync(baselinePath, `${lines.join('\n')}\n`, 'utf8');
  } catch {
    // Ignore
  }
}

/**
 * Initialize SQLite database schema and seed default Issuer, Attacker & Key Inventory.
 * @param {string} [customDbPath] - File path or ':memory:'
 * @returns {DatabaseSync}
 */
export function initDatabase(customDbPath) {
  const resolvedPath =
    customDbPath || process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'vault.db');

  if (activeDb && activeDbPath === resolvedPath) {
    return activeDb;
  }

  if (activeDb) {
    closeDatabase();
  }

  if (resolvedPath !== ':memory:') {
    const dir = path.dirname(path.resolve(resolvedPath));
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new DatabaseSync(resolvedPath);
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'ISSUER',
      password_hash TEXT NOT NULL,
      totp_secret TEXT NOT NULL,
      totp_enabled INTEGER NOT NULL DEFAULT 1,
      public_key_pem TEXT NOT NULL,
      private_key_pem TEXT NOT NULL,
      key_fingerprint TEXT NOT NULL,
      spki_fingerprint_sha256 TEXT NOT NULL DEFAULT '',
      signing_pin TEXT NOT NULL DEFAULT 'UIT-SIGN-2026',
      failed_pin_attempts INTEGER NOT NULL DEFAULT 0,
      account_locked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS key_inventory (
      key_id TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      algorithm TEXT NOT NULL DEFAULT 'RSA-OAEP-SHA256',
      key_size_bits INTEGER NOT NULL DEFAULT 2048,
      fingerprint_sha256_spki TEXT NOT NULL,
      created_at TEXT NOT NULL,
      notes TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      sha256_hash TEXT NOT NULL,
      signature TEXT NOT NULL,
      issuer_id INTEGER NOT NULL,
      issuer_name TEXT NOT NULL,
      public_key_fingerprint TEXT NOT NULL,
      storage_filename TEXT NOT NULL,
      iv_hex TEXT NOT NULL,
      auth_tag_hex TEXT NOT NULL,
      visibility TEXT NOT NULL DEFAULT 'PUBLIC',
      key_id TEXT NOT NULL DEFAULT 'vault-rsa-prod-2026Q4',
      wrapped_dek_b64 TEXT NOT NULL DEFAULT '',
      aad_b64 TEXT NOT NULL DEFAULT '',
      backup_encrypted_base64 TEXT NOT NULL,
      backup_signature TEXT NOT NULL,
      backup_iv_hex TEXT NOT NULL,
      backup_auth_tag_hex TEXT NOT NULL,
      backup_wrapped_dek_b64 TEXT NOT NULL DEFAULT '',
      backup_aad_b64 TEXT NOT NULL DEFAULT '',
      backup_key_id TEXT NOT NULL DEFAULT 'vault-rsa-prod-2026Q4',
      is_tampered_demo INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (issuer_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS share_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      document_id TEXT NOT NULL,
      created_by TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      access_count INTEGER NOT NULL DEFAULT 0,
      revoked INTEGER NOT NULL DEFAULT 0,
      recipient_email TEXT NOT NULL DEFAULT 'linh.tran@company.vn',
      created_at TEXT NOT NULL,
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'INFO',
      actor TEXT NOT NULL,
      document_id TEXT,
      ip_address TEXT,
      details TEXT,
      created_at TEXT NOT NULL
    );
  `);

  const alterStatements = [
    "ALTER TABLE users ADD COLUMN spki_fingerprint_sha256 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN signing_pin TEXT NOT NULL DEFAULT 'UIT-SIGN-2026'",
    'ALTER TABLE users ADD COLUMN failed_pin_attempts INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN account_locked INTEGER NOT NULL DEFAULT 0',
    "ALTER TABLE documents ADD COLUMN visibility TEXT NOT NULL DEFAULT 'PUBLIC'",
    "ALTER TABLE documents ADD COLUMN key_id TEXT NOT NULL DEFAULT 'vault-rsa-prod-2026Q4'",
    "ALTER TABLE documents ADD COLUMN wrapped_dek_b64 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE documents ADD COLUMN aad_b64 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE documents ADD COLUMN backup_wrapped_dek_b64 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE documents ADD COLUMN backup_aad_b64 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE documents ADD COLUMN backup_key_id TEXT NOT NULL DEFAULT 'vault-rsa-prod-2026Q4'",
    'ALTER TABLE share_links ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0',
    "ALTER TABLE share_links ADD COLUMN recipient_email TEXT NOT NULL DEFAULT 'linh.tran@company.vn'",
  ];
  for (const sql of alterStatements) {
    try {
      db.exec(sql);
    } catch {
      // Column already exists
    }
  }

  activeDb = db;
  activeDbPath = resolvedPath;

  seedDefaultUsersAndKeys(db);
  syncKeyInventoryCsv();
  syncHashBaselineFile();

  return db;
}

/**
 * Seed default Issuer, Attacker, and Key Inventory (ACTIVE, RETIRED, QA_ONLY).
 * @param {DatabaseSync} db
 */
function seedDefaultUsersAndKeys(db) {
  let existingIssuer = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get('issuer_admin');

  const nowIso = new Date().toISOString();

  if (!existingIssuer) {
    const issuerKeys = generateRsaKeyPair();
    const issuerFingerprint = getPublicKeyFingerprint(issuerKeys.publicKeyPem);
    const spkiHex = getSpkiSha256Fingerprint(issuerKeys.publicKeyPem);
    const passwordHash = bcrypt.hashSync('Admin@123', 10);

    db.prepare(`
      INSERT INTO users (
        username, display_name, role, password_hash,
        totp_secret, totp_enabled, public_key_pem, private_key_pem,
        key_fingerprint, spki_fingerprint_sha256, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'issuer_admin',
      'Phòng Đào Tạo & Khảo Thí (Issuer)',
      'ISSUER',
      passwordHash,
      DEFAULT_ISSUER_TOTP_SECRET,
      1,
      issuerKeys.publicKeyPem,
      issuerKeys.privateKeyPem,
      issuerFingerprint,
      spkiHex,
      nowIso
    );
    existingIssuer = db.prepare('SELECT * FROM users WHERE username = ?').get('issuer_admin');
  } else if (!existingIssuer.spki_fingerprint_sha256) {
    const spkiHex = getSpkiSha256Fingerprint(existingIssuer.public_key_pem);
    db.prepare('UPDATE users SET spki_fingerprint_sha256 = ? WHERE id = ?').run(
      spkiHex,
      existingIssuer.id
    );
    existingIssuer.spki_fingerprint_sha256 = spkiHex;
  }

  let existingAttacker = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get('mallory_attacker');

  if (!existingAttacker) {
    const attackerKeys = generateRsaKeyPair();
    const attackerFingerprint = getPublicKeyFingerprint(attackerKeys.publicKeyPem);
    const attackerSpkiHex = getSpkiSha256Fingerprint(attackerKeys.publicKeyPem);
    const passwordHash = bcrypt.hashSync('Attacker@123', 10);

    db.prepare(`
      INSERT INTO users (
        username, display_name, role, password_hash,
        totp_secret, totp_enabled, public_key_pem, private_key_pem,
        key_fingerprint, spki_fingerprint_sha256, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'mallory_attacker',
      'Mallory (Kẻ tấn công giả định)',
      'ATTACKER',
      passwordHash,
      'MZXW6YTBOI======',
      1,
      attackerKeys.publicKeyPem,
      attackerKeys.privateKeyPem,
      attackerFingerprint,
      attackerSpkiHex,
      nowIso
    );
    existingAttacker = db
      .prepare('SELECT * FROM users WHERE username = ?')
      .get('mallory_attacker');
  } else if (!existingAttacker.spki_fingerprint_sha256) {
    const attackerSpkiHex = getSpkiSha256Fingerprint(existingAttacker.public_key_pem);
    db.prepare('UPDATE users SET spki_fingerprint_sha256 = ? WHERE id = ?').run(
      attackerSpkiHex,
      existingAttacker.id
    );
    existingAttacker.spki_fingerprint_sha256 = attackerSpkiHex;
  }

  // Seed Lab 4 Key Inventory (ACTIVE, RETIRED, QA_ONLY)
  const upsertKey = db.prepare(`
    INSERT INTO key_inventory (
      key_id, status, algorithm, key_size_bits, fingerprint_sha256_spki, created_at, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(key_id) DO UPDATE SET
      fingerprint_sha256_spki = excluded.fingerprint_sha256_spki
  `);

  upsertKey.run(
    DEFAULT_ACTIVE_KEY_ID,
    'ACTIVE',
    'RSA-OAEP-SHA256',
    2048,
    existingIssuer.spki_fingerprint_sha256,
    '2026-10-01',
    'Current production KEK/Issuer key; fingerprint is SHA-256 of DER SubjectPublicKeyInfo'
  );
  upsertKey.run(
    'vault-rsa-retired-2026Q3',
    'RETIRED',
    'RSA-OAEP-SHA256',
    2048,
    '57b6afd548daa42bb33fd0d9f0f2ddee5fe6de12cbc8ff754801d50c2a52ae07',
    '2026-07-01',
    'Retired key; included only in migration archive'
  );
  upsertKey.run(
    'vault-rsa-qa-2026Q4',
    'QA_ONLY',
    'RSA-OAEP-SHA256',
    2048,
    existingAttacker.spki_fingerprint_sha256,
    '2026-10-05',
    'Test environment key; must not decrypt production envelopes'
  );
}

/**
 * Retrieve the active database instance, initializing if necessary.
 * @returns {DatabaseSync}
 */
export function getDatabase() {
  if (!activeDb) {
    return initDatabase();
  }
  return activeDb;
}

/**
 * Cleanly close the active SQLite database connection.
 */
export function closeDatabase() {
  if (activeDb) {
    try {
      activeDb.close();
    } catch {
      // Ignore already closed errors
    }
    activeDb = null;
    activeDbPath = null;
  }
}

/**
 * Fetch a key inventory entry by key_id.
 * @param {string} keyId
 * @returns {object|undefined}
 */
export function getKeyInventoryById(keyId) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM key_inventory WHERE key_id = ?').get(keyId);
}

/**
 * List all keys in key_inventory.
 * @returns {Array<object>}
 */
export function listKeyInventory() {
  const db = getDatabase();
  return db.prepare('SELECT * FROM key_inventory ORDER BY created_at DESC').all();
}

/**
 * Record an entry into the audit_logs table.
 */
export function logAuditEvent({
  eventType,
  severity = 'INFO',
  actor = 'anonymous',
  documentId = null,
  ipAddress = '127.0.0.1',
  details = '',
}) {
  const db = getDatabase();
  const detailsText =
    typeof details === 'string' ? details : JSON.stringify(details);
  const createdAt = new Date().toISOString();

  const result = db
    .prepare(`
      INSERT INTO audit_logs (
        event_type, severity, actor, document_id, ip_address, details, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      eventType,
      severity,
      actor,
      documentId || null,
      ipAddress || '127.0.0.1',
      detailsText,
      createdAt
    );

  return {
    id: Number(result.lastInsertRowid),
    eventType,
    severity,
    actor,
    documentId,
    ipAddress,
    details: detailsText,
    createdAt,
  };
}

export function getUserByUsername(username) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

export function getUserById(id) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

/**
 * Insert a new signed & encrypted document record (with Hybrid DEK/KEK, AAD & Visibility).
 * @param {object} doc
 * @returns {object}
 */
export function insertDocument(doc) {
  const db = getDatabase();
  const visibility =
    String(doc.visibility || 'PUBLIC').toUpperCase() === 'PRIVATE' ? 'PRIVATE' : 'PUBLIC';
  const keyId = doc.keyId || DEFAULT_ACTIVE_KEY_ID;
  const wrappedDekB64 = doc.wrappedDekBase64 || '';
  const aadB64 = doc.aadBase64 || '';

  db.prepare(`
    INSERT INTO documents (
      id, title, original_filename, mime_type, file_size,
      sha256_hash, signature, issuer_id, issuer_name, public_key_fingerprint,
      storage_filename, iv_hex, auth_tag_hex,
      visibility, key_id, wrapped_dek_b64, aad_b64,
      backup_encrypted_base64, backup_signature, backup_iv_hex, backup_auth_tag_hex,
      backup_wrapped_dek_b64, backup_aad_b64, backup_key_id,
      is_tampered_demo, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    doc.id,
    doc.title,
    doc.originalFilename,
    doc.mimeType,
    doc.fileSize,
    doc.sha256Hash,
    doc.signature,
    doc.issuerId,
    doc.issuerName,
    doc.publicKeyFingerprint,
    doc.storageFilename,
    doc.ivHex,
    doc.authTagHex,
    visibility,
    keyId,
    wrappedDekB64,
    aadB64,
    doc.backupEncryptedBase64,
    doc.backupSignature,
    doc.backupIvHex,
    doc.backupAuthTagHex,
    wrappedDekB64,
    aadB64,
    keyId,
    0,
    doc.createdAt
  );

  syncHashBaselineFile();
  return getDocumentById(doc.id);
}

/**
 * Fetch a single document by ID, joined with issuer's public and private keys.
 * @param {string} id
 * @returns {object|undefined}
 */
export function getDocumentById(id) {
  const db = getDatabase();
  return db
    .prepare(`
      SELECT
        d.*,
        u.public_key_pem AS issuer_public_key_pem,
        u.private_key_pem AS issuer_private_key_pem,
        u.spki_fingerprint_sha256 AS issuer_spki_fingerprint_sha256,
        u.username AS issuer_username
      FROM documents d
      LEFT JOIN users u ON d.issuer_id = u.id
      WHERE d.id = ?
    `)
    .get(id);
}

/**
 * Delete a document and all of its associated share links from SQLite, then sync hash baseline.
 * @param {string} id
 * @returns {{ deletedSharesCount: number, deletedDocChanges: number }}
 */
export function deleteDocumentById(id) {
  const db = getDatabase();
  const shareRes = db
    .prepare('DELETE FROM share_links WHERE document_id = ?')
    .run(id);
  const docRes = db
    .prepare('DELETE FROM documents WHERE id = ?')
    .run(id);
  syncHashBaselineFile();
  return {
    deletedSharesCount: Number(shareRes.changes) || 0,
    deletedDocChanges: Number(docRes.changes) || 0,
  };
}

/**
 * List documents ordered by newest first, optionally filtered by visibility ('PUBLIC' | 'PRIVATE').
 * @param {{ visibility?: string }} [options]
 * @returns {Array<object>}
 */
export function listDocuments(options = {}) {
  const db = getDatabase();
  const rows = db
    .prepare(`
      SELECT
        d.id, d.title, d.original_filename, d.mime_type, d.file_size,
        d.sha256_hash, d.signature, d.issuer_id, d.issuer_name,
        d.public_key_fingerprint, d.storage_filename, d.iv_hex, d.auth_tag_hex,
        d.visibility, d.key_id, d.wrapped_dek_b64, d.aad_b64,
        d.is_tampered_demo, d.created_at,
        u.public_key_pem AS issuer_public_key_pem
      FROM documents d
      LEFT JOIN users u ON d.issuer_id = u.id
      ORDER BY d.created_at DESC
    `)
    .all();

  if (options && options.visibility) {
    const targetVis = String(options.visibility).toUpperCase();
    return rows.filter(
      (r) => String(r.visibility || 'PUBLIC').toUpperCase() === targetVis
    );
  }
  return rows;
}

export function listAuditLogs(limit = 50) {
  const db = getDatabase();
  return db
    .prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?')
    .all(Number(limit) || 50);
}

export function createShareLink({
  token,
  documentId,
  createdBy,
  recipientEmail = 'linh.tran@company.vn',
  expiresAt,
  createdAt,
}) {
  const db = getDatabase();
  const nowIso = createdAt || new Date().toISOString();
  db.prepare(`
    INSERT INTO share_links (
      token, document_id, created_by, recipient_email, expires_at, access_count, created_at
    )
    VALUES (?, ?, ?, ?, ?, 0, ?)
  `).run(token, documentId, createdBy, recipientEmail, expiresAt, nowIso);
  return getShareLinkByToken(token);
}

export function listShareLinks() {
  const db = getDatabase();
  return db
    .prepare(`
      SELECT
        s.id, s.token, s.document_id, s.created_by, s.recipient_email,
        s.expires_at, s.access_count, s.revoked, s.created_at,
        d.original_filename, d.title, d.file_size, d.issuer_name
      FROM share_links s
      LEFT JOIN documents d ON s.document_id = d.id
      ORDER BY s.id DESC
    `)
    .all();
}

export function getShareLinkByToken(token) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM share_links WHERE token = ?').get(token);
}

export function incrementShareLinkAccess(token) {
  const db = getDatabase();
  db.prepare('UPDATE share_links SET access_count = access_count + 1 WHERE token = ?').run(token);
}

export function recordFailedPinAttempt(username) {
  const db = getDatabase();
  const user = getUserByUsername(username);
  if (!user) {
    return { failedAttempts: 0, locked: false, remainingAttempts: 3, revokedLinksCount: 0 };
  }

  const nextCount = (Number(user.failed_pin_attempts) || 0) + 1;
  const shouldLock = nextCount >= 3 ? 1 : 0;

  db.prepare(
    'UPDATE users SET failed_pin_attempts = ?, account_locked = ? WHERE username = ?'
  ).run(nextCount, shouldLock, username);

  let revokedLinksCount = 0;
  if (shouldLock) {
    const res = db
      .prepare('UPDATE share_links SET revoked = 1 WHERE created_by = ? AND revoked = 0')
      .run(username);
    revokedLinksCount = Number(res.changes) || 0;
  }

  return {
    failedAttempts: nextCount,
    locked: Boolean(shouldLock),
    remainingAttempts: Math.max(0, 3 - nextCount),
    revokedLinksCount,
  };
}

export function lockAccountEmergency(username = 'issuer_admin') {
  const db = getDatabase();
  db.prepare(
    'UPDATE users SET failed_pin_attempts = 3, account_locked = 1 WHERE username = ?'
  ).run(username);
  const res = db
    .prepare('UPDATE share_links SET revoked = 1 WHERE created_by = ?')
    .run(username);
  return {
    locked: true,
    revokedLinksCount: Number(res.changes) || 0,
  };
}

export function resetAccountSecurityState(username = 'issuer_admin') {
  const db = getDatabase();
  db.prepare(
    'UPDATE users SET failed_pin_attempts = 0, account_locked = 0 WHERE username = ?'
  ).run(username);
  const futureIso = new Date(Date.now() + 900 * 1000).toISOString();
  db.prepare(
    'UPDATE share_links SET revoked = 0, expires_at = ? WHERE created_by = ?'
  ).run(futureIso, username);
}
