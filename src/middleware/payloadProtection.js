import crypto from 'node:crypto';

/**
 * Shared 256-bit (32-byte) Zero-Trust Transport Protection Key used between the SPA Frontend
 * and Express Backend for AES-256-GCM Payload Encryption and HMAC-SHA256 Anti-Replay Signing.
 */
export const ZT_TRANSPORT_SECRET_PASSPHRASE =
  process.env.ZT_TRANSPORT_SECRET || 'zt-vault-transport-protection-2026-key';

export const ZT_TRANSPORT_KEY = crypto
  .createHash('sha256')
  .update(ZT_TRANSPORT_SECRET_PASSPHRASE, 'utf8')
  .digest();

const REPLAY_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const usedNonces = new Map();

const FUZZ_WINDOW_MS = 60 * 1000; // 1 minute window
const FUZZ_THRESHOLD = 10; // Block IP after 10 blackhole / malformed violations within 1 minute
const fuzzViolationsByIp = new Map();

function cleanupExpiredNonces(now = Date.now()) {
  for (const [nonce, seenAt] of usedNonces.entries()) {
    if (now - seenAt > REPLAY_WINDOW_MS) {
      usedNonces.delete(nonce);
    }
  }
}

export function resetReplayNonceCache() {
  usedNonces.clear();
}

export function resetAntiFuzzingState() {
  fuzzViolationsByIp.clear();
}

function getClientIp(req) {
  return String(req.headers['x-simulated-ip'] || req.ip || '127.0.0.1').trim();
}

function pruneFuzzWindow(ip, now = Date.now()) {
  const timestamps = fuzzViolationsByIp.get(ip);
  if (!timestamps) return [];
  const active = timestamps.filter((t) => now - t <= FUZZ_WINDOW_MS);
  if (active.length === 0) {
    fuzzViolationsByIp.delete(ip);
  } else {
    fuzzViolationsByIp.set(ip, active);
  }
  return active;
}

function isIpFuzzBlocked(ip, now = Date.now()) {
  const active = pruneFuzzWindow(ip, now);
  return active.length >= FUZZ_THRESHOLD;
}

function recordFuzzViolation(ip, now = Date.now()) {
  const active = pruneFuzzWindow(ip, now);
  active.push(now);
  fuzzViolationsByIp.set(ip, active);
  return active.length;
}

/**
 * Encrypt a JSON-serializable object into a compact AES-256-GCM envelope string:
 * `<ivHex12B>.<ciphertextBase64>.<authTagHex16B>`
 * @param {object} payloadObj
 * @returns {string}
 */
export function encryptTransportPayload(payloadObj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ZT_TRANSPORT_KEY, iv);
  const plaintext = Buffer.from(JSON.stringify(payloadObj ?? {}), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}.${encrypted.toString('base64')}.${authTag.toString('hex')}`;
}

/**
 * Decrypt a `<ivHex12B>.<ciphertextBase64>.<authTagHex16B>` string back into a parsed JSON object.
 * @param {string} envelopeStr
 * @returns {object}
 */
export function decryptTransportPayload(envelopeStr) {
  const parts = String(envelopeStr || '').split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted payload envelope');
  }
  const [ivHex, cipherB64, tagHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const ciphertext = Buffer.from(cipherB64, 'base64');
  const authTag = Buffer.from(tagHex, 'hex');

  if (iv.length !== 12 || authTag.length !== 16) {
    throw new Error('Invalid IV or Auth Tag length in encrypted payload');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', ZT_TRANSPORT_KEY, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

/**
 * Compute HMAC-SHA256 anti-replay request signature:
 * `HMAC_SHA256(key, "${method}|${path}|${timestamp}|${nonce}|${payloadDigest}")`
 * @param {{ method: string, urlPath: string, timestamp: string|number, nonce: string, payloadString?: string }} params
 * @returns {string}
 */
export function signRequestAntiReplay({
  method,
  urlPath,
  timestamp,
  nonce,
  payloadString = '',
}) {
  const payloadHash = crypto
    .createHash('sha256')
    .update(String(payloadString || ''), 'utf8')
    .digest('hex');
  const canonical = `${String(method || 'GET').toUpperCase()}|${urlPath}|${timestamp}|${nonce}|${payloadHash}`;
  return crypto
    .createHmac('sha256', ZT_TRANSPORT_KEY)
    .update(canonical, 'utf8')
    .digest('hex');
}

/**
 * Express middleware enforcing:
 * - Layer 4: Anti-Fuzzing Guard (HTTP 429 ANTI_FUZZING_BLOCKED after >= 10 violations / 60s per IP)
 * - Layer 2: Strict Zero-Trust Tunnel Mode (404 Blackhole for any direct `/api/*` request outside `POST /api/zt-tunnel`)
 * - Anti-Replay Protection (HMAC-SHA256 + Timestamp + Nonce via timingSafeEqual)
 * - Two-Way AES-256-GCM Tunnel Decryption (`ztEncryptedPayload`) & Response Encryption (`ztEncryptedResponse`)
 */
export function zeroTrustPayloadProtection(req, res, next) {
  res.setHeader('X-ZT-Transport-Protection', 'AES-256-GCM+HMAC-SHA256');
  res.setHeader('Cache-Control', 'no-store');

  const now = Date.now();
  const clientIp = getClientIp(req);

  // Layer 4: Anti-Fuzzing Guard check before processing
  if (isIpFuzzBlocked(clientIp, now)) {
    return res.status(429).json({
      errorCode: 'ANTI_FUZZING_BLOCKED',
      message:
        'Địa chỉ IP đã bị tạm khóa tự động do phát hiện hành vi quét đường dẫn hoặc gửi gói tin bất thường liên tiếp (Anti-Fuzzing Guard).',
    });
  }

  // Encrypt outgoing JSON response when client requests AES-256-GCM transport protection
  if (String(req.headers['x-zt-encrypted'] || '').toUpperCase() === 'AES-256-GCM') {
    const originalJson = res.json.bind(res);
    res.json = (data) => {
      if (data && typeof data === 'object' && typeof data.ztEncryptedResponse === 'string') {
        return originalJson(data);
      }
      res.setHeader('X-ZT-Response-Encrypted', 'AES-256-GCM');
      return originalJson({
        ztEncryptedResponse: encryptTransportPayload(data),
      });
    };
  }

  // Layer 2: Strict Zero-Trust Tunnel Mode - ONLY allow POST /api/zt-tunnel with encrypted envelope
  const isTunnelEndpoint =
    req.method === 'POST' &&
    (req.originalUrl === '/api/zt-tunnel' ||
      req.url === '/zt-tunnel' ||
      req.path === '/zt-tunnel' ||
      req.path === '/api/zt-tunnel');

  const hasEncryptedEnvelope =
    req.body && typeof req.body.ztEncryptedPayload === 'string' && req.body.ztEncryptedPayload.length > 0;

  const tsHeader = req.headers['x-zt-timestamp'];
  const nonceHeader = req.headers['x-zt-nonce'];
  const sigHeader = req.headers['x-zt-signature'];
  const hasAntiReplayHeaders =
    tsHeader !== undefined && nonceHeader !== undefined && sigHeader !== undefined;

  if (!isTunnelEndpoint || !hasEncryptedEnvelope || !hasAntiReplayHeaders) {
    recordFuzzViolation(clientIp, now);
    return res.status(404).json({
      errorCode: 'NOT_FOUND',
      message: 'Not Found',
    });
  }

  // Validate Anti-Replay Headers (Timestamp + Nonce + HMAC-SHA256)
  const tsNum = Number(tsHeader);
  const nonce = String(nonceHeader || '').trim();
  const signature = String(sigHeader || '').trim().toLowerCase();

  if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > REPLAY_WINDOW_MS) {
    recordFuzzViolation(clientIp, now);
    return res.status(401).json({
      errorCode: 'REPLAY_TIMESTAMP_EXPIRED',
      message:
        'Từ chối yêu cầu: Dấu thời gian (Timestamp) của gói tin không hợp lệ hoặc đã quá hạn 5 phút.',
    });
  }

  if (!nonce || nonce.length < 16) {
    recordFuzzViolation(clientIp, now);
    return res.status(401).json({
      errorCode: 'INVALID_REPLAY_NONCE',
      message: 'Từ chối yêu cầu: Mã định danh gói tin một lần (Nonce) không hợp lệ.',
    });
  }

  cleanupExpiredNonces(now);
  if (usedNonces.has(nonce)) {
    recordFuzzViolation(clientIp, now);
    return res.status(409).json({
      errorCode: 'REPLAY_NONCE_DETECTED',
      message:
        'Phát hiện tấn công phát lại (Replay Attack): Gói tin có mã Nonce này đã được thực thi trước đó!',
    });
  }

  const payloadString = req.body.ztEncryptedPayload;
  const expectedSig = signRequestAntiReplay({
    method: req.method,
    urlPath: req.originalUrl,
    timestamp: tsNum,
    nonce,
    payloadString,
  });

  const sigBuf = Buffer.from(signature, 'hex');
  const expBuf = Buffer.from(expectedSig, 'hex');
  if (
    sigBuf.length !== expBuf.length ||
    sigBuf.length === 0 ||
    !crypto.timingSafeEqual(sigBuf, expBuf)
  ) {
    recordFuzzViolation(clientIp, now);
    return res.status(401).json({
      errorCode: 'INVALID_REQUEST_SIGNATURE',
      message:
        'Từ chối yêu cầu: Chữ ký toàn vẹn gói tin (X-ZT-Signature HMAC-SHA256) không hợp lệ!',
    });
  }

  usedNonces.set(nonce, now);
  res.setHeader('X-ZT-Verified-Request', 'HMAC-SHA256-OK');

  // Decrypt AES-256-GCM Tunnel Envelope and rewrite request for Express router
  try {
    const decryptedObj = decryptTransportPayload(req.body.ztEncryptedPayload);
    if (
      !decryptedObj ||
      typeof decryptedObj !== 'object' ||
      typeof decryptedObj.path !== 'string' ||
      !decryptedObj.path.startsWith('/')
    ) {
      recordFuzzViolation(clientIp, now);
      return res.status(400).json({
        errorCode: 'INVALID_ENCRYPTED_PAYLOAD',
        message: 'Cấu trúc gói tin đường hầm không hợp lệ.',
      });
    }

    // Check if inner path targets an unknown / removed route (e.g. legacy simulation routes) -> record fuzz violation
    if (decryptedObj.path.startsWith('/api/attack/')) {
      recordFuzzViolation(clientIp, now);
      return res.status(404).json({
        errorCode: 'NOT_FOUND',
        message: 'Not Found',
      });
    }

    let parsedBody = decryptedObj.body;
    if (typeof parsedBody === 'string' && parsedBody.trim().length > 0) {
      try {
        parsedBody = JSON.parse(parsedBody);
      } catch {
        // Keep string if not JSON
      }
    }
    if (!parsedBody || typeof parsedBody !== 'object') {
      parsedBody = {};
    }

    // Unpack Base64 file upload (`__ztFile`) into `req.file` for seamless Multer-compatible upload handling
    if (parsedBody.__ztFile && typeof parsedBody.__ztFile === 'object') {
      const ztFile = parsedBody.__ztFile;
      const fileBuf = Buffer.from(String(ztFile.base64 || ''), 'base64');
      req.file = {
        fieldname: String(ztFile.fieldname || 'file'),
        originalname: String(ztFile.originalname || 'document.bin'),
        encoding: '7bit',
        mimetype: String(ztFile.mimetype || 'application/octet-stream'),
        buffer: fileBuf,
        size: fileBuf.length,
      };
      delete parsedBody.__ztFile;
    }

    if (decryptedObj.headers && typeof decryptedObj.headers === 'object') {
      for (const [k, v] of Object.entries(decryptedObj.headers)) {
        const lowerK = k.toLowerCase();
        if (req.headers[lowerK] === undefined && v !== undefined) {
          req.headers[lowerK] = String(v);
        }
      }
    }

    req.method = String(decryptedObj.method || 'GET').toUpperCase();
    req.url = decryptedObj.path;
    req.originalUrl = decryptedObj.path;
    req.body = parsedBody;
    req.isZtTunnel = true;
    req.isPayloadEncrypted = true;
    res.setHeader('X-ZT-Payload-Decrypted', 'AES-256-GCM-OK');
    res.setHeader('X-ZT-Tunnel-Routed', 'AES-256-GCM-TUNNEL-OK');

    const qIndex = decryptedObj.path.indexOf('?');
    if (qIndex !== -1) {
      req.query = Object.fromEntries(new URLSearchParams(decryptedObj.path.slice(qIndex + 1)));
    }

    if (req.baseUrl && req.url.startsWith(req.baseUrl)) {
      req.url = req.url.slice(req.baseUrl.length) || '/';
    }
  } catch {
    recordFuzzViolation(clientIp, now);
    return res.status(400).json({
      errorCode: 'INVALID_ENCRYPTED_PAYLOAD',
      message:
        'Giải mã gói tin thất bại: Payload AES-256-GCM đã bị can thiệp hoặc sai định dạng.',
    });
  }

  return next();
}
