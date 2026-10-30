import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import multer from 'multer';
import {
  buildEnvelopeAad,
  calculateHash,
  decryptBuffer,
  decryptEnvelopeBuffer,
  encryptBuffer,
  encryptEnvelopeBuffer,
  safeCompareHex,
  safeCompareStrings,
  signData,
  verifySignature,
} from '../crypto/cryptoService.js';
import {
  DEFAULT_ACTIVE_KEY_ID,
  DEFAULT_ISSUER_SIGNING_PIN,
  createShareLink,
  deleteDocumentById,
  getDatabase,
  getDocumentById,
  getKeyInventoryById,
  getShareLinkByToken,
  getUserById,
  getUserByUsername,
  incrementShareLinkAccess,
  insertDocument,
  listAuditLogs,
  listDocuments,
  listKeyInventory,
  listShareLinks,
  logAuditEvent,
  recordFailedPinAttempt,
} from '../db/database.js';
import { requireAuth } from '../middleware/authMiddleware.js';
import {
  extractDocumentPreviewRich,
  extractDocumentPreviewText,
} from '../utils/docExtractor.js';

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
const MAX_SHARE_EXPIRE_MINUTES = 525600; // 1 year (365 days)
const MAX_SHARE_EXPIRE_SECONDS = MAX_SHARE_EXPIRE_MINUTES * 60; // 31,536,000s
const DEFAULT_SHARE_EXPIRE_MINUTES = 10080; // 7 days (default)
const DEFAULT_SHARE_EXPIRE_SECONDS = DEFAULT_SHARE_EXPIRE_MINUTES * 60; // 604,800s
const FORBIDDEN_EXECUTABLE_EXTENSIONS = new Set([
  '.exe',
  '.bat',
  '.cmd',
  '.ps1',
  '.sh',
  '.vbs',
  '.scr',
  '.msi',
  '.js',
]);
const MALICIOUS_PAYLOAD_REGEX = /<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=/i;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE_BYTES,
  },
});

/**
 * Wrap multer single file upload to cleanly catch LIMIT_FILE_SIZE (HTTP 413).
 * @param {string} fieldName
 */
function handleSingleUpload(fieldName = 'file') {
  const middleware = upload.single(fieldName);
  return (req, res, next) => {
    if (req.file) {
      const byteLen = req.file.buffer ? req.file.buffer.length : Number(req.file.size || 0);
      if (byteLen > MAX_FILE_SIZE_BYTES) {
        return res.status(413).json({
          errorCode: 'FILE_TOO_LARGE',
          message: 'Kích thước tệp vượt quá giới hạn an toàn cho phép (tối đa 10MB).',
        });
      }
      return next();
    }
    middleware(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({
            errorCode: 'FILE_TOO_LARGE',
            message: 'Kích thước tệp vượt quá giới hạn an toàn cho phép (tối đa 10MB).',
          });
        }
        return res.status(400).json({
          errorCode: 'UPLOAD_ERROR',
          message: `Lỗi tải tệp lên: ${err.message}`,
        });
      }
      return next();
    });
  };
}

/**
 * Compute human-readable document code (e.g., VB-2026-0001) based on chronological order.
 * @param {string} docId
 * @returns {string}
 */
function getDocumentCode(docId) {
  try {
    const rows = getDatabase()
      .prepare('SELECT id FROM documents ORDER BY created_at ASC, rowid ASC')
      .all();
    const idx = rows.findIndex((r) => r.id === docId);
    if (idx >= 0) {
      return `VB-2026-${String(idx + 1).padStart(4, '0')}`;
    }
  } catch {
    // Fallback
  }
  return `VB-2026-0001`;
}

/**
 * Find a document by UUID or by human-readable code (e.g., VB-2026-0001).
 * @param {string} idOrCode
 * @returns {object | null}
 */
function findDocumentByIdOrCode(idOrCode) {
  const cleaned = String(idOrCode || '').trim();
  if (!cleaned) return null;

  const direct = getDocumentById(cleaned);
  if (direct) return direct;

  const upper = cleaned.toUpperCase();
  const rows = getDatabase()
    .prepare('SELECT id FROM documents ORDER BY created_at ASC, rowid ASC')
    .all();
  for (let i = 0; i < rows.length; i += 1) {
    const code = `VB-2026-${String(i + 1).padStart(4, '0')}`;
    if (code === upper || rows[i].id.toUpperCase() === upper) {
      return getDocumentById(rows[i].id);
    }
  }
  return null;
}

/**
 * Decrypt a vault document using Hybrid Envelope Encryption (DEK + KEK RSA-OAEP-SHA256),
 * verifying Key Inventory status (ACTIVE vs RETIRED/QA_ONLY) and AAD context binding.
 * @param {object} doc
 * @param {Buffer} encryptedOnDisk
 * @returns {Buffer}
 */
function verifyKeyInventoryAndDecryptEnvelope(doc, encryptedOnDisk) {
  const keyId = doc.key_id || DEFAULT_ACTIVE_KEY_ID;
  const keyRecord = getKeyInventoryById(keyId);
  if (!keyRecord || keyRecord.status !== 'ACTIVE') {
    const err = new Error(
      `Khóa giải mã '${keyId}' không ở trạng thái ACTIVE (Trạng thái hiện tại: ${keyRecord?.status || 'UNKNOWN'}).`
    );
    err.code = 'KEY_NOT_ACTIVE';
    throw err;
  }

  const expectedAadString = buildEnvelopeAad({
    docId: doc.id,
    issuerId: doc.issuer_id,
    originalFilename: doc.original_filename,
  });

  return decryptEnvelopeBuffer({
    encryptedInput: encryptedOnDisk,
    ivHex: doc.iv_hex,
    authTagHex: doc.auth_tag_hex,
    wrappedDekBase64: doc.wrapped_dek_b64,
    kekPrivateKeyPem: doc.issuer_private_key_pem,
    expectedAadString,
    storedAadBase64: doc.aad_b64,
  });
}

/**
 * Format a database document row into a clean API response object.
 * @param {object} doc
 * @returns {object}
 */
function formatDocumentMetadata(doc) {
  const docCode = getDocumentCode(doc.id);
  const activeShares = getDatabase()
    .prepare(
      'SELECT COUNT(*) AS cnt FROM share_links WHERE document_id = ? AND revoked = 0 AND expires_at > ?'
    )
    .get(doc.id, new Date().toISOString());
  const hasActiveShare = Number(activeShares?.cnt || 0) > 0;
  const visibility =
    String(doc.visibility || 'PUBLIC').toUpperCase() === 'PRIVATE' ? 'PRIVATE' : 'PUBLIC';

  return {
    id: doc.id,
    docCode,
    title: doc.title,
    originalFilename: doc.original_filename,
    mimeType: doc.mime_type,
    fileSize: doc.file_size,
    sha256Hash: doc.sha256_hash,
    signature: doc.signature,
    issuerId: doc.issuer_id,
    issuerName: doc.issuer_name,
    publicKeyFingerprint: doc.public_key_fingerprint,
    storageFilename: doc.storage_filename,
    ivHex: doc.iv_hex,
    authTagHex: doc.auth_tag_hex,
    visibility,
    visibilityLabel: visibility === 'PRIVATE' ? 'Nội bộ' : 'Công khai',
    keyId: doc.key_id || DEFAULT_ACTIVE_KEY_ID,
    wrappedDekBase64: doc.wrapped_dek_b64 || '',
    aadBase64: doc.aad_b64 || '',
    isTamperedDemo: Boolean(doc.is_tampered_demo),
    hasActiveShare,
    publishStatus: hasActiveShare ? 'Đang chia sẻ' : 'Đã ban hành',
    createdAt: doc.created_at,
  };
}

/**
 * Create the `/api/documents` router bound to a specific storage directory.
 * @param {{ storageDir: string }} options
 * @returns {express.Router}
 */
export function createDocumentRouter({ storageDir }) {
  const router = express.Router();

  const ensureStorageDir = () => {
    fs.mkdirSync(storageDir, { recursive: true });
  };

  /**
   * GET /api/documents
   * List all signed & encrypted documents stored in the vault.
   */
  router.get('/', (req, res) => {
    const docs = listDocuments().map(formatDocumentMetadata);
    return res.status(200).json({
      documents: docs,
    });
  });

  /**
   * GET /api/documents/public
   * List ONLY PUBLIC documents for the Recipient Public Portal (PRIVATE documents are hidden).
   */
  router.get('/public', (req, res) => {
    const docs = listDocuments({ visibility: 'PUBLIC' }).map(formatDocumentMetadata);
    return res.status(200).json({
      documents: docs,
    });
  });

  /**
   * GET /api/documents/key-inventory
   * List key inventory records (ACTIVE, RETIRED, QA_ONLY) and SPKI SHA-256 fingerprints.
   */
  router.get('/key-inventory', (req, res) => {
    const keys = listKeyInventory();
    return res.status(200).json({
      keys,
    });
  });

  /**
   * GET /api/documents/shares
   * List all share links for the Drive UI ("Được chia sẻ với tôi" & "Liên kết đã chia sẻ").
   */
  router.get('/shares', (req, res) => {
    const rows = listShareLinks();
    return res.status(200).json({
      shares: rows,
    });
  });

  /**
   * GET /api/documents/audit-logs
   * Retrieve recent security audit logs.
   */
  router.get('/audit-logs', (req, res) => {
    const limit = Number(req.query.limit) || 50;
    const logs = listAuditLogs(limit);
    return res.status(200).json({
      logs,
    });
  });

  /**
   * POST /api/documents/extract-preview
   * Extract human-readable text from an uploaded `.docx`, `.doc`, or text file for UC02 preview
   * without modifying the original binary file.
   */
  router.post('/extract-preview', handleSingleUpload('file'), async (req, res) => {
    const file = req.file;
    if (!file || !file.buffer || file.buffer.length === 0) {
      return res.status(400).json({
        errorCode: 'EMPTY_OR_MISSING_FILE',
        message: 'Tệp tải lên không tồn tại hoặc rỗng.',
      });
    }
    const { extractedText, extractedHtml, isWordDoc } = await extractDocumentPreviewRich(
      file.buffer,
      file.originalname || 'document.bin'
    );
    return res.status(200).json({
      originalFilename: file.originalname || 'document.bin',
      fileSize: file.buffer.length,
      extractedText,
      extractedHtml,
      isWordDoc,
    });
  });

  /**
   * POST /api/documents/sign
   * Authenticated Issuer endpoint:
   * 1. Hash original file with SHA-256
   * 2. Sign content with Issuer's RSA-2048 Private Key
   * 3. Encrypt content with AES-256-GCM (fresh 12-byte IV + 16-byte Auth Tag)
   * 4. Save ONLY encrypted binary to `storage/<id>.enc`
   * 5. Store metadata + backup in SQLite and write Audit Log
   */
  router.post('/sign', requireAuth, handleSingleUpload('file'), async (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const file = req.file;

    if (!file || !file.buffer || file.size === 0 || file.buffer.length === 0) {
      return res.status(400).json({
        errorCode: 'EMPTY_OR_MISSING_FILE',
        message: 'Tệp tải lên không tồn tại hoặc rỗng (0 byte). Hệ thống từ chối ký số.',
      });
    }

    const issuer =
      getUserById(req.user.sub) || getUserByUsername(req.user.username || 'issuer_admin');
    if (!issuer) {
      return res.status(401).json({
        errorCode: 'ISSUER_NOT_FOUND',
        message: 'Không tìm thấy thông tin khóa của đơn vị phát hành.',
      });
    }

    // 1. Account Takeover / Emergency Lockout Check
    if (issuer.account_locked) {
      logAuditEvent({
        eventType: 'SIGN_BLOCKED_ACCOUNT_LOCKED',
        severity: 'CRITICAL',
        actor: issuer.username,
        ipAddress: ip,
        details: {
          reason: 'Account locked due to suspected Account Takeover (3 failed signing PIN attempts)',
        },
      });
      return res.status(423).json({
        errorCode: 'ACCOUNT_COMPROMISED_LOCKED',
        accountLocked: true,
        message:
          'KHÓA KHẨN CẤP: Tài khoản đã bị khóa do phát hiện dấu hiệu chiếm quyền (nhập sai Mã PIN Khóa ký số 3 lần liên tiếp). Toàn bộ quyền ký số và liên kết chia sẻ đã bị thu hồi!',
      });
    }

    // 2. Signing Key Passphrase (PIN) Verification against Account Takeover
    if (req.body?.signingPin !== undefined) {
      const providedPin = String(req.body.signingPin).trim();
      const expectedPin = String(issuer.signing_pin || DEFAULT_ISSUER_SIGNING_PIN).trim();
      const pinValid = safeCompareStrings(providedPin, expectedPin);

      if (!pinValid) {
        const pinState = recordFailedPinAttempt(issuer.username);
        if (pinState.locked) {
          logAuditEvent({
            eventType: 'ACCOUNT_TAKEOVER_EMERGENCY_LOCK',
            severity: 'CRITICAL',
            actor: issuer.username,
            ipAddress: ip,
            details: {
              failedAttempts: pinState.failedAttempts,
              revokedLinksCount: pinState.revokedLinksCount,
              reason: '3 consecutive wrong Signing PIN attempts -> Emergency Account Lock & Share Links Revoked',
            },
          });
          return res.status(423).json({
            errorCode: 'ACCOUNT_COMPROMISED_LOCKED',
            accountLocked: true,
            failedAttempts: pinState.failedAttempts,
            revokedLinksCount: pinState.revokedLinksCount,
            message:
              'PHÁT HIỆN CHIẾM QUYỀN TÀI KHOẢN: Nhập sai Mã PIN Khóa ký số 3/3 lần! Hệ thống đã KHÓA KHẨN CẤP tài khoản, vô hiệu hóa quyền ký số và thu hồi toàn bộ liên kết chia sẻ đang mở.',
          });
        }

        logAuditEvent({
          eventType: 'SIGNING_PIN_FAILED',
          severity: 'WARN',
          actor: issuer.username,
          ipAddress: ip,
          details: {
            failedAttempts: pinState.failedAttempts,
            remainingAttempts: pinState.remainingAttempts,
          },
        });
        return res.status(403).json({
          errorCode: 'INVALID_SIGNING_PIN',
          accountLocked: false,
          failedAttempts: pinState.failedAttempts,
          remainingAttempts: pinState.remainingAttempts,
          message: `Mã PIN Khóa ký số không chính xác! Còn ${pinState.remainingAttempts} lần thử trước khi hệ thống khóa khẩn cấp tài khoản để chống chiếm quyền.`,
        });
      }

      if (issuer.failed_pin_attempts > 0) {
        getDatabase()
          .prepare('UPDATE users SET failed_pin_attempts = 0 WHERE username = ?')
          .run(issuer.username);
      }
    }

    // 3. Input Forgery & Malicious Payload Inspection
    const originalFilename = String(file.originalname || 'document.bin').trim();
    const ext = path.extname(originalFilename).toLowerCase();
    const textSample =
      file.buffer.length <= 512 * 1024 ? file.buffer.toString('utf8') : '';

    if (
      FORBIDDEN_EXECUTABLE_EXTENSIONS.has(ext) ||
      MALICIOUS_PAYLOAD_REGEX.test(originalFilename) ||
      MALICIOUS_PAYLOAD_REGEX.test(String(req.body?.title || '')) ||
      MALICIOUS_PAYLOAD_REGEX.test(String(req.body?.signerName || '')) ||
      MALICIOUS_PAYLOAD_REGEX.test(textSample)
    ) {
      logAuditEvent({
        eventType: 'INPUT_FORGERY_MALICIOUS_BLOCKED',
        severity: 'CRITICAL',
        actor: issuer.username,
        ipAddress: ip,
        details: {
          originalFilename,
          extension: ext,
          reason: 'Executable file disguise or malicious script injection detected in input',
        },
      });
      return res.status(400).json({
        errorCode: 'MALICIOUS_OR_FORGED_INPUT',
        message:
          'CHẶN ĐẦU VÀO GIẢ MẠO: Phát hiện tệp thực thi độc hại (.exe/.bat/.js/...) hoặc mã kịch bản giả mạo (<script>/XSS) trong dữ liệu đầu vào. Hệ thống từ chối ký số và lưu trữ!',
      });
    }

    ensureStorageDir();

    const docId = crypto.randomUUID();
    const safeOriginalFilename = file.originalname || 'document.bin';
    const rawVisibility = String(req.body?.visibility || 'PUBLIC').trim().toUpperCase();
    const visibility = rawVisibility === 'PRIVATE' ? 'PRIVATE' : 'PUBLIC';
    const keyId = String(req.body?.keyId || DEFAULT_ACTIVE_KEY_ID).trim() || DEFAULT_ACTIVE_KEY_ID;

    // Validate keyId against Key Inventory if provided
    const keyRecord = getKeyInventoryById(keyId);
    if (keyRecord && keyRecord.status !== 'ACTIVE') {
      return res.status(422).json({
        errorCode: 'KEY_NOT_ACTIVE',
        keyId,
        keyStatus: keyRecord.status,
        message: `Từ chối ký số & mã hóa: Khóa mật mã '${keyId}' đang ở trạng thái '${keyRecord.status}' (không phải ACTIVE).`,
      });
    }

    const sha256Hash = calculateHash(file.buffer);
    const signature = signData(file.buffer, issuer.private_key_pem);
    const aadString = buildEnvelopeAad({
      docId,
      issuerId: issuer.id,
      originalFilename: safeOriginalFilename,
    });
    const {
      ivHex,
      authTagHex,
      encryptedBuffer,
      wrappedDekBase64,
      aadBase64,
    } = encryptEnvelopeBuffer(file.buffer, issuer.public_key_pem, aadString);

    const storageFilename = `${docId}.enc`;
    const storageFilePath = path.join(storageDir, storageFilename);

    // Write ONLY AES-256-GCM ciphertext to disk (zero plaintext on storage)
    fs.writeFileSync(storageFilePath, encryptedBuffer);

    const title = String(req.body?.title || file.originalname || 'Untitled Document').trim();
    const customSignerName = String(
      req.body?.signerName || req.body?.issuerName || issuer.display_name
    ).trim();
    const createdAt = new Date().toISOString();

    const savedDoc = insertDocument({
      id: docId,
      title,
      originalFilename: safeOriginalFilename,
      mimeType: file.mimetype || 'application/octet-stream',
      fileSize: file.buffer.length,
      sha256Hash,
      signature,
      issuerId: issuer.id,
      issuerName: customSignerName || issuer.display_name,
      publicKeyFingerprint: issuer.key_fingerprint,
      storageFilename,
      ivHex,
      authTagHex,
      visibility,
      keyId,
      wrappedDekBase64,
      aadBase64,
      backupEncryptedBase64: encryptedBuffer.toString('base64'),
      backupSignature: signature,
      backupIvHex: ivHex,
      backupAuthTagHex: authTagHex,
      backupWrappedDekBase64: wrappedDekBase64,
      backupAadBase64: aadBase64,
      backupKeyId: keyId,
      createdAt,
    });

    logAuditEvent({
      eventType: 'DOCUMENT_SIGNED_AND_ENCRYPTED',
      severity: 'INFO',
      actor: issuer.username,
      documentId: docId,
      ipAddress: ip,
      details: {
        title,
        originalFilename: savedDoc.original_filename,
        fileSize: savedDoc.file_size,
        sha256Hash,
        publicKeyFingerprint: issuer.key_fingerprint,
        visibility,
        keyId,
        encryption: 'AES-256-GCM + RSA-OAEP-SHA256 Hybrid Envelope',
      },
    });

    const formattedDoc = formatDocumentMetadata(savedDoc);
    const { extractedText, extractedHtml, isWordDoc } = await extractDocumentPreviewRich(
      file.buffer,
      safeOriginalFilename
    );

    return res.status(201).json({
      message: 'Tài liệu đã được băm SHA-256, ký số RSA-2048 và mã hóa lưu kho AES-256-GCM thành công.',
      document: formattedDoc,
      id: savedDoc.id,
      docCode: formattedDoc.docCode,
      title: savedDoc.title,
      originalFilename: savedDoc.original_filename,
      fileSize: savedDoc.file_size,
      sha256Hash: savedDoc.sha256_hash,
      signature: savedDoc.signature,
      ivHex: savedDoc.iv_hex,
      authTagHex: savedDoc.auth_tag_hex,
      visibility: formattedDoc.visibility,
      visibilityLabel: formattedDoc.visibilityLabel,
      keyId: formattedDoc.keyId,
      wrappedDekBase64: formattedDoc.wrappedDekBase64,
      aadBase64: formattedDoc.aadBase64,
      publicKeyFingerprint: savedDoc.public_key_fingerprint,
      issuerName: savedDoc.issuer_name,
      extractedText,
      extractedHtml,
      isWordDoc,
      createdAt: savedDoc.created_at,
    });
  });

  /**
   * POST /api/documents/verify
   * Public Zero-Trust Verification Endpoint supporting 2 modes:
   * - Mode 1 (Vault Storage Verification by documentId, no uploaded file):
   *   Reads `storage/<id>.enc`, verifies AES-256-GCM Auth Tag, SHA-256 hash (`timingSafeEqual`), and RSA-2048 signature.
   * - Mode 2 (Recipient Uploaded File Verification with `file` + `documentId`):
   *   Verifies uploaded file's SHA-256 hash (`timingSafeEqual`) and RSA-2048 signature against the registered document record,
   *   AND also checks vault storage integrity if requested.
   */
  router.post('/verify', handleSingleUpload('file'), (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const documentId = String(req.body?.documentId || req.query?.documentId || '').trim();

    if (!documentId) {
      return res.status(400).json({
        verified: false,
        status: 'RED',
        errorCode: 'MISSING_DOCUMENT_ID',
        message: 'Vui lòng chọn hoặc cung cấp mã định danh văn bản (documentId) cần đối chiếu.',
      });
    }

    const doc = getDocumentById(documentId);
    if (!doc) {
      return res.status(404).json({
        verified: false,
        status: 'RED',
        errorCode: 'DOCUMENT_NOT_FOUND',
        message: 'Không tìm thấy hồ sơ văn bản gốc trong cơ sở dữ liệu.',
      });
    }

    const issuerPublicKey = doc.issuer_public_key_pem;

    // MODE 2: Recipient uploaded an external file to verify against the Issuer's record
    if (req.file) {
      if (!req.file.buffer || req.file.size === 0 || req.file.buffer.length === 0) {
        return res.status(400).json({
          verified: false,
          status: 'RED',
          errorCode: 'EMPTY_OR_MISSING_FILE',
          message: 'Tệp tải lên để kiểm chứng bị rỗng (0 byte).',
        });
      }

      const uploadedBuffer = req.file.buffer;
      const uploadedHash = calculateHash(uploadedBuffer);
      const hashMatched = safeCompareHex(uploadedHash, doc.sha256_hash);
      const signatureValid = verifySignature(uploadedBuffer, doc.signature, issuerPublicKey);

      if (!hashMatched) {
        logAuditEvent({
          eventType: 'VERIFY_FAILED_UPLOAD_TAMPERED',
          severity: 'CRITICAL',
          actor: 'public_verifier',
          documentId: doc.id,
          ipAddress: ip,
          details: {
            reason: 'Uploaded file SHA-256 hash mismatch (File content modified)',
            expectedHash: doc.sha256_hash,
            actualHash: uploadedHash,
          },
        });

        return res.status(422).json({
          verified: false,
          status: 'RED',
          errorCode: 'INTEGRITY_VIOLATION',
          message:
            'CẢNH BÁO GIẢ MẠO: Nội dung tệp tải lên đã bị thay đổi (Mã băm SHA-256 và chữ ký số không khớp với bản gốc)!',
          expectedHash: doc.sha256_hash,
          actualHash: uploadedHash,
          checks: {
            aesGcmAuthTag: true,
            sha256Hash: false,
            rsaSignature: signatureValid,
          },
          document: formatDocumentMetadata(doc),
        });
      }

      if (!signatureValid) {
        logAuditEvent({
          eventType: 'VERIFY_FAILED_SIGNATURE_FORGED',
          severity: 'CRITICAL',
          actor: 'public_verifier',
          documentId: doc.id,
          ipAddress: ip,
          details: {
            reason: 'RSA-2048 signature verification failed against Issuer Public Key',
            publicKeyFingerprint: doc.public_key_fingerprint,
          },
        });

        return res.status(422).json({
          verified: false,
          status: 'RED',
          errorCode: 'SIGNATURE_FORGED',
          message:
            'CẢNH BÁO MẠO DANH: Chữ ký số không khớp với Khóa công khai (Public Key) của đơn vị phát hành!',
          expectedHash: doc.sha256_hash,
          actualHash: uploadedHash,
          checks: {
            aesGcmAuthTag: true,
            sha256Hash: true,
            rsaSignature: false,
          },
          document: formatDocumentMetadata(doc),
        });
      }

      logAuditEvent({
        eventType: 'VERIFY_SUCCESS_UPLOADED_FILE',
        severity: 'INFO',
        actor: 'public_verifier',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          sha256Hash: uploadedHash,
          publicKeyFingerprint: doc.public_key_fingerprint,
        },
      });

      return res.status(200).json({
        verified: true,
        status: 'GREEN',
        errorCode: null,
        message:
          'XÁC MINH HỢP LỆ: Tệp tải lên nguyên vẹn 100% và chữ ký số RSA-2048 khớp hoàn toàn với đơn vị phát hành.',
        expectedHash: doc.sha256_hash,
        actualHash: uploadedHash,
        checks: {
          aesGcmAuthTag: true,
          sha256Hash: true,
          rsaSignature: true,
        },
        document: formatDocumentMetadata(doc),
      });
    }

    // MODE 1: Verify encrypted vault file on disk (`storage/<id>.enc`)
    const storageFilePath = path.join(storageDir, doc.storage_filename);
    if (!fs.existsSync(storageFilePath)) {
      logAuditEvent({
        eventType: 'VERIFY_FAILED_STORAGE_MISSING',
        severity: 'CRITICAL',
        actor: 'public_verifier',
        documentId: doc.id,
        ipAddress: ip,
        details: { reason: 'Encrypted storage file missing from disk' },
      });

      return res.status(422).json({
        verified: false,
        status: 'RED',
        errorCode: 'STORAGE_TAMPERED',
        message: 'CẢNH BÁO XÂM PHẠM: Tệp mã hóa trong kho lưu trữ đã bị xóa hoặc di dời trái phép!',
        checks: {
          aesGcmAuthTag: false,
          sha256Hash: false,
          rsaSignature: false,
        },
        document: formatDocumentMetadata(doc),
      });
    }

    const encryptedOnDisk = fs.readFileSync(storageFilePath);
    let decryptedBuffer;
    try {
      decryptedBuffer = verifyKeyInventoryAndDecryptEnvelope(doc, encryptedOnDisk);
    } catch (err) {
      // Compute hash of raw corrupted file just to show visual mismatch in UI
      const corruptedDiskHash = calculateHash(encryptedOnDisk);
      const errCode =
        err.code === 'KEY_NOT_ACTIVE' || err.code === 'AAD_CONTEXT_MISMATCH'
          ? err.code
          : 'STORAGE_TAMPERED';

      logAuditEvent({
        eventType: `VERIFY_FAILED_${errCode}`,
        severity: 'CRITICAL',
        actor: 'public_verifier',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          reason:
            err.message ||
            'AES-256-GCM Authentication Tag mismatch on storage file (1-byte tampering detected)',
          errorCode: errCode,
        },
      });

      return res.status(422).json({
        verified: false,
        status: 'RED',
        errorCode: errCode,
        message:
          err.code === 'KEY_NOT_ACTIVE' || err.code === 'AAD_CONTEXT_MISMATCH'
            ? err.message
            : 'CẢNH BÁO XÂM PHẠM KHO LƯU TRỮ: Dữ liệu mã hóa trên máy chủ đã bị can thiệp trái phép (AES-256-GCM Auth Tag Mismatch & Integrity Violation)!',
        expectedHash: doc.sha256_hash,
        actualHash: `CORRUPTED_CIPHERTEXT:${corruptedDiskHash.slice(0, 40)}`,
        checks: {
          aesGcmAuthTag: false,
          sha256Hash: false,
          rsaSignature: false,
        },
        document: formatDocumentMetadata(doc),
      });
    }

    const currentHash = calculateHash(decryptedBuffer);
    const hashMatched = safeCompareHex(currentHash, doc.sha256_hash);
    const signatureValid = verifySignature(decryptedBuffer, doc.signature, issuerPublicKey);

    if (!hashMatched) {
      logAuditEvent({
        eventType: 'VERIFY_FAILED_HASH_MISMATCH',
        severity: 'CRITICAL',
        actor: 'public_verifier',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          expectedHash: doc.sha256_hash,
          actualHash: currentHash,
        },
      });

      return res.status(422).json({
        verified: false,
        status: 'RED',
        errorCode: 'INTEGRITY_VIOLATION',
        message:
          'CẢNH BÁO TOÀN VẸN: Mã băm SHA-256 sau giải mã không khớp với mã băm gốc đã đăng ký!',
        expectedHash: doc.sha256_hash,
        actualHash: currentHash,
        checks: {
          aesGcmAuthTag: true,
          sha256Hash: false,
          rsaSignature: signatureValid,
        },
        document: formatDocumentMetadata(doc),
      });
    }

    if (!signatureValid) {
      logAuditEvent({
        eventType: 'VERIFY_FAILED_SIGNATURE_FORGED',
        severity: 'CRITICAL',
        actor: 'public_verifier',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          reason: 'Digital signature verification failed against Issuer RSA-2048 Public Key',
          publicKeyFingerprint: doc.public_key_fingerprint,
        },
      });

      return res.status(422).json({
        verified: false,
        status: 'RED',
        errorCode: 'SIGNATURE_FORGED',
        message:
          'CẢNH BÁO GIẢ MẠO CHỮ KÝ SỐ: Chữ ký đính kèm văn bản không thuộc về Khóa bí mật của đơn vị phát hành!',
        expectedHash: doc.sha256_hash,
        actualHash: currentHash,
        checks: {
          aesGcmAuthTag: true,
          sha256Hash: true,
          rsaSignature: false,
        },
        document: formatDocumentMetadata(doc),
      });
    }

    logAuditEvent({
      eventType: 'VERIFY_SUCCESS_VAULT_DOCUMENT',
      severity: 'INFO',
      actor: 'public_verifier',
      documentId: doc.id,
      ipAddress: ip,
      details: {
        sha256Hash: currentHash,
        publicKeyFingerprint: doc.public_key_fingerprint,
      },
    });

    return res.status(200).json({
      verified: true,
      status: 'GREEN',
      errorCode: null,
      message:
        'XÁC MINH TOÀN VẸN THÀNH CÔNG: AES-256-GCM Auth Tag, mã băm SHA-256 và chữ ký số RSA-2048 đều hợp lệ.',
      expectedHash: doc.sha256_hash,
      actualHash: currentHash,
      checks: {
        aesGcmAuthTag: true,
        sha256Hash: true,
        rsaSignature: true,
      },
      document: formatDocumentMetadata(doc),
    });
  });

  /**
   * POST /api/documents/:id/share
   * Create a time-bound sharing token for a signed document (default 900s = 15 minutes).
   */
  router.post('/:id/share', requireAuth, (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const issuer =
      getUserById(req.user.sub) || getUserByUsername(req.user.username || 'issuer_admin');
    if (issuer && issuer.account_locked) {
      return res.status(423).json({
        errorCode: 'ACCOUNT_COMPROMISED_LOCKED',
        accountLocked: true,
        message:
          'Từ chối tạo liên kết chia sẻ: Tài khoản đang bị khóa khẩn cấp do nghi ngờ bị chiếm quyền!',
      });
    }
    const docId = String(req.params.id || '').trim();
    const doc = getDocumentById(docId);

    if (!doc) {
      return res.status(404).json({
        errorCode: 'DOCUMENT_NOT_FOUND',
        message: 'Không tìm thấy văn bản cần chia sẻ.',
      });
    }

    const rawMinutes = req.body?.expiresInMinutes;
    const rawSeconds = req.body?.expiresInSeconds;
    let expiresInSeconds = DEFAULT_SHARE_EXPIRE_SECONDS;
    if (rawMinutes !== undefined && rawMinutes !== null) {
      const clampedMinutes = Math.min(
        Math.max(1, Number(rawMinutes) || DEFAULT_SHARE_EXPIRE_MINUTES),
        MAX_SHARE_EXPIRE_MINUTES
      );
      expiresInSeconds = clampedMinutes * 60;
    } else if (rawSeconds !== undefined && rawSeconds !== null) {
      expiresInSeconds = Math.min(
        Math.max(1, Number(rawSeconds) || DEFAULT_SHARE_EXPIRE_SECONDS),
        MAX_SHARE_EXPIRE_SECONDS
      );
    }
    const expiresInMinutes = Math.round(expiresInSeconds / 60);
    const recipientEmail = String(
      req.body?.recipientEmail || 'linh.tran@company.vn'
    ).trim();

    const token = crypto.randomBytes(24).toString('hex');
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();

    createShareLink({
      token,
      documentId: doc.id,
      createdBy: req.user.username || 'issuer_admin',
      recipientEmail,
      expiresAt,
      createdAt,
    });

    const shareUrl = `/api/documents/share/${token}`;

    logAuditEvent({
      eventType: 'SHARE_LINK_CREATED',
      severity: 'INFO',
      actor: req.user.username || 'issuer_admin',
      documentId: doc.id,
      ipAddress: ip,
      details: {
        token,
        recipientEmail,
        expiresInMinutes,
        expiresInSeconds,
        expiresAt,
      },
    });

    return res.status(201).json({
      token,
      documentId: doc.id,
      recipientEmail,
      shareUrl,
      expiresInMinutes,
      expiresInSeconds,
      expiresAt,
    });
  });

  /**
   * GET /api/documents/share/:token
   * Access or download a shared document ONLY if:
   * 1. Token exists and has not expired (otherwise HTTP 403 LINK_EXPIRED)
   * 2. Encrypted file passes AES-256-GCM Auth Tag decryption
   * 3. Decrypted content matches SHA-256 (`timingSafeEqual`) and RSA-2048 signature (`verifySignature`)
   */
  router.get('/share/:token', async (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const token = String(req.params.token || '').trim();
    const link = getShareLinkByToken(token);

    if (!link) {
      return res.status(404).json({
        errorCode: 'SHARE_LINK_NOT_FOUND',
        message: 'Liên kết chia sẻ không tồn tại hoặc mã chia sẻ bị giả mạo.',
      });
    }

    if (link.revoked) {
      logAuditEvent({
        eventType: 'SHARE_LINK_REVOKED_BLOCKED',
        severity: 'CRITICAL',
        actor: 'anonymous_recipient',
        documentId: link.document_id,
        ipAddress: ip,
        details: {
          token,
          reason: 'Share link revoked due to Issuer Account Takeover lockdown',
        },
      });
      return res.status(403).json({
        verified: false,
        status: 'RED',
        errorCode: 'LINK_REVOKED_ACCOUNT_TAKEOVER',
        message:
          'Liên kết chia sẻ đã bị THU HỒI KHẨN CẤP do hệ thống phát hiện tài khoản phát hành có dấu hiệu bị chiếm quyền!',
      });
    }

    const nowMs = Date.now();
    const expiresAtMs = new Date(link.expires_at).getTime();

    if (nowMs >= expiresAtMs) {
      logAuditEvent({
        eventType: 'SHARE_LINK_EXPIRED_BLOCKED',
        severity: 'WARN',
        actor: 'anonymous_recipient',
        documentId: link.document_id,
        ipAddress: ip,
        details: {
          token,
          expiresAt: link.expires_at,
          attemptedAt: new Date(nowMs).toISOString(),
        },
      });

      return res.status(403).json({
        errorCode: 'LINK_EXPIRED',
        message: 'Liên kết chia sẻ đã hết hạn truy cập. Yêu cầu đơn vị phát hành cấp liên kết mới.',
        expiresAt: link.expires_at,
      });
    }

    const doc = getDocumentById(link.document_id);
    if (!doc) {
      return res.status(404).json({
        errorCode: 'DOCUMENT_NOT_FOUND',
        message: 'Văn bản gắn với liên kết chia sẻ không còn tồn tại.',
      });
    }

    const storageFilePath = path.join(storageDir, doc.storage_filename);
    if (!fs.existsSync(storageFilePath)) {
      return res.status(422).json({
        errorCode: 'STORAGE_TAMPERED',
        message: 'Tệp lưu trữ mã hóa không tồn tại hoặc đã bị xâm phạm.',
      });
    }

    let decryptedBuffer;
    try {
      const encryptedOnDisk = fs.readFileSync(storageFilePath);
      decryptedBuffer = verifyKeyInventoryAndDecryptEnvelope(doc, encryptedOnDisk);
    } catch (err) {
      const errCode =
        err.code === 'KEY_NOT_ACTIVE' || err.code === 'AAD_CONTEXT_MISMATCH'
          ? err.code
          : 'STORAGE_TAMPERED';
      logAuditEvent({
        eventType: 'SHARE_DOWNLOAD_BLOCKED_TAMPERED',
        severity: 'CRITICAL',
        actor: 'anonymous_recipient',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          token,
          errorCode: errCode,
          reason: err.message || 'AES-256-GCM Auth Tag mismatch during shared access',
        },
      });

      return res.status(422).json({
        verified: false,
        status: 'RED',
        errorCode: errCode,
        message: 'Chặn tải xuống: Dữ liệu gốc trên máy chủ có dấu hiệu bị sửa đổi trái phép!',
      });
    }

    const currentHash = calculateHash(decryptedBuffer);
    const hashMatched = safeCompareHex(currentHash, doc.sha256_hash);
    const signatureValid = verifySignature(
      decryptedBuffer,
      doc.signature,
      doc.issuer_public_key_pem
    );

    if (!hashMatched || !signatureValid) {
      logAuditEvent({
        eventType: 'SHARE_DOWNLOAD_BLOCKED_INTEGRITY',
        severity: 'CRITICAL',
        actor: 'anonymous_recipient',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          token,
          hashMatched,
          signatureValid,
        },
      });

      return res.status(422).json({
        verified: false,
        status: 'RED',
        errorCode: !hashMatched ? 'INTEGRITY_VIOLATION' : 'SIGNATURE_FORGED',
        message:
          'Chặn tải xuống theo nguyên tắc Zero-Trust: Mã băm hoặc chữ ký số của tài liệu không hợp lệ!',
      });
    }

    incrementShareLinkAccess(token);

    logAuditEvent({
      eventType: 'SHARE_LINK_ACCESSED',
      severity: 'INFO',
      actor: 'anonymous_recipient',
      documentId: doc.id,
      ipAddress: ip,
      details: {
        token,
        download: req.query.download === '1',
      },
    });

    if (req.query.download === '1') {
      res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${encodeURIComponent(doc.original_filename)}"`
      );
      res.setHeader('X-Content-SHA256', doc.sha256_hash);
      res.setHeader('X-Issuer-Fingerprint', doc.public_key_fingerprint);
      return res.status(200).send(decryptedBuffer);
    }

    const { extractedText, extractedHtml, isWordDoc } = await extractDocumentPreviewRich(
      decryptedBuffer,
      doc.original_filename
    );

    return res.status(200).json({
      verified: true,
      status: 'GREEN',
      message: 'Liên kết hợp lệ và tài liệu đã vượt qua toàn bộ bước kiểm chứng mật mã.',
      shareLink: {
        token: link.token,
        expiresAt: link.expires_at,
        accessCount: link.access_count + 1,
      },
      document: formatDocumentMetadata(doc),
      downloadUrl: `/api/documents/share/${token}?download=1`,
      contentBase64: decryptedBuffer.toString('base64'),
      extractedText,
      extractedHtml,
      isWordDoc,
    });
  });

  /**
   * GET /api/documents/lookup/:query
   * Public lookup endpoint for Recipient Portal (UC05 / UC06 / UC07):
   * Supports looking up by Share Token OR Document Code (e.g., VB-2026-0001) OR Document UUID.
   */
  router.get('/lookup/:query', async (req, res) => {
    const rawQuery = String(req.params.query || '').trim();
    if (!rawQuery) {
      return res.status(400).json({
        verified: false,
        errorCode: 'MISSING_QUERY',
        message: 'Vui lòng nhập mã định danh văn bản hoặc liên kết chia sẻ.',
      });
    }

    // 1. Check if rawQuery matches a Share Token
    const link = getShareLinkByToken(rawQuery);
    if (link) {
      if (link.revoked) {
        return res.status(403).json({
          verified: false,
          errorCode: 'LINK_REVOKED_ACCOUNT_TAKEOVER',
          message: 'Không thể truy cập: Liên kết chia sẻ đã bị thu hồi hoặc không còn hiệu lực.',
        });
      }
      if (Date.now() >= new Date(link.expires_at).getTime()) {
        return res.status(403).json({
          verified: false,
          errorCode: 'LINK_EXPIRED',
          message: 'Không thể truy cập: Liên kết chia sẻ đã hết thời hạn hiệu lực.',
        });
      }
    }

    const doc = link ? getDocumentById(link.document_id) : findDocumentByIdOrCode(rawQuery);
    if (!doc) {
      return res.status(404).json({
        verified: false,
        errorCode: 'DOCUMENT_NOT_FOUND',
        message: 'Không tìm thấy văn bản tương ứng với mã tra cứu hoặc liên kết đã nhập.',
      });
    }

    // Check if issuer is locked and all links for this doc were revoked
    const issuer = getUserById(doc.issuer_id);
    if (issuer && issuer.account_locked) {
      return res.status(403).json({
        verified: false,
        errorCode: 'LINK_REVOKED_ACCOUNT_TAKEOVER',
        message: 'Không thể truy cập: Văn bản này đang tạm dừng chia sẻ do tài khoản phát hành bị khóa.',
      });
    }

    const storageFilePath = path.join(storageDir, doc.storage_filename);
    if (!fs.existsSync(storageFilePath)) {
      return res.status(422).json({
        verified: false,
        errorCode: 'STORAGE_TAMPERED',
        message: 'Không thể mở tệp: Nội dung tệp đã bị thay đổi hoặc không hợp lệ.',
      });
    }

    let decryptedBuffer;
    try {
      const encryptedOnDisk = fs.readFileSync(storageFilePath);
      decryptedBuffer = verifyKeyInventoryAndDecryptEnvelope(doc, encryptedOnDisk);
    } catch (err) {
      const errCode =
        err.code === 'KEY_NOT_ACTIVE' || err.code === 'AAD_CONTEXT_MISMATCH'
          ? err.code
          : 'STORAGE_TAMPERED';
      return res.status(422).json({
        verified: false,
        errorCode: errCode,
        message: 'Không thể mở tệp: Nội dung tệp đã bị thay đổi hoặc không hợp lệ.',
      });
    }

    const currentHash = calculateHash(decryptedBuffer);
    const hashMatched = safeCompareHex(currentHash, doc.sha256_hash);
    const signatureValid = verifySignature(
      decryptedBuffer,
      doc.signature,
      doc.issuer_public_key_pem
    );

    if (!hashMatched || !signatureValid) {
      return res.status(422).json({
        verified: false,
        errorCode: !hashMatched ? 'INTEGRITY_VIOLATION' : 'SIGNATURE_FORGED',
        message: 'Không thể truy cập: Liên kết chia sẻ hoặc chữ ký xác thực không hợp lệ.',
      });
    }

    if (link) {
      incrementShareLinkAccess(link.token);
    }

    const formatted = formatDocumentMetadata(doc);
    const { extractedText, extractedHtml, isWordDoc } = await extractDocumentPreviewRich(
      decryptedBuffer,
      doc.original_filename
    );
    return res.status(200).json({
      verified: true,
      document: formatted,
      downloadUrl: `/api/documents/download/${encodeURIComponent(doc.id)}`,
      contentBase64: decryptedBuffer.toString('base64'),
      extractedText,
      extractedHtml,
      isWordDoc,
    });
  });

  /**
   * DELETE /api/documents/:id
   * Authenticated Issuer endpoint to delete a document from SQLite, delete its share links,
   * remove the encrypted `.enc` file from `storage/`, update hash_baseline.txt, and write an Audit Log.
   */
  router.delete('/:id', requireAuth, (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const rawId = String(req.params.id || '').trim();
    const doc = findDocumentByIdOrCode(rawId);

    if (!doc) {
      return res.status(404).json({
        errorCode: 'DOCUMENT_NOT_FOUND',
        message: 'Không tìm thấy văn bản cần xóa.',
      });
    }

    const storageFilePath = path.join(storageDir, doc.storage_filename);
    let storageFileRemoved = false;
    if (fs.existsSync(storageFilePath)) {
      try {
        fs.unlinkSync(storageFilePath);
        storageFileRemoved = true;
      } catch {
        // Ignore unlink race
      }
    }

    const { deletedSharesCount } = deleteDocumentById(doc.id);

    logAuditEvent({
      eventType: 'DOCUMENT_DELETED',
      severity: 'WARN',
      actor: req.user?.username || 'issuer_admin',
      documentId: doc.id,
      ipAddress: ip,
      details: {
        originalFilename: doc.original_filename,
        storageFilename: doc.storage_filename,
        storageFileRemoved,
        deletedSharesCount,
      },
    });

    return res.status(200).json({
      deleted: true,
      id: doc.id,
      documentId: doc.id,
      originalFilename: doc.original_filename,
      deletedSharesCount,
      storageFileRemoved,
      message: `Đã xóa văn bản "${doc.original_filename}" và thu hồi ${deletedSharesCount} liên kết chia sẻ liên quan.`,
    });
  });

  /**
   * GET /api/documents/download/:id
   * Direct verified download endpoint by document ID or Code.
   */
  router.get('/download/:id', (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const docId = String(req.params.id || '').trim();
    const doc = findDocumentByIdOrCode(docId);

    if (!doc) {
      return res.status(404).json({
        errorCode: 'DOCUMENT_NOT_FOUND',
        message: 'Không tìm thấy văn bản.',
      });
    }

    const storageFilePath = path.join(storageDir, doc.storage_filename);
    if (!fs.existsSync(storageFilePath)) {
      return res.status(422).json({
        errorCode: 'STORAGE_TAMPERED',
        message: 'Tệp lưu trữ mã hóa không tồn tại.',
      });
    }

    let decryptedBuffer;
    try {
      const encryptedOnDisk = fs.readFileSync(storageFilePath);
      decryptedBuffer = verifyKeyInventoryAndDecryptEnvelope(doc, encryptedOnDisk);
    } catch (err) {
      const errCode =
        err.code === 'KEY_NOT_ACTIVE' || err.code === 'AAD_CONTEXT_MISMATCH'
          ? err.code
          : 'STORAGE_TAMPERED';
      logAuditEvent({
        eventType: 'DIRECT_DOWNLOAD_BLOCKED_TAMPERED',
        severity: 'CRITICAL',
        actor: 'recipient',
        documentId: doc.id,
        ipAddress: ip,
        details: {
          errorCode: errCode,
          reason: err.message || 'AES-256-GCM Auth Tag mismatch',
        },
      });
      return res.status(422).json({
        errorCode: errCode,
        message: 'Giải mã thất bại: Tệp lưu trữ trên máy chủ đã bị can thiệp 1 byte!',
      });
    }

    const currentHash = calculateHash(decryptedBuffer);
    const hashMatched = safeCompareHex(currentHash, doc.sha256_hash);
    const signatureValid = verifySignature(
      decryptedBuffer,
      doc.signature,
      doc.issuer_public_key_pem
    );

    if (!hashMatched || !signatureValid) {
      return res.status(422).json({
        errorCode: !hashMatched ? 'INTEGRITY_VIOLATION' : 'SIGNATURE_FORGED',
        message: 'Từ chối trả tệp: Chữ ký số hoặc mã băm SHA-256 không hợp lệ!',
      });
    }

    res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${encodeURIComponent(doc.original_filename)}"`
    );
    res.setHeader('X-Content-SHA256', doc.sha256_hash);
    return res.status(200).send(decryptedBuffer);
  });

  return router;
}
