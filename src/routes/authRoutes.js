import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {
  generateTotpCode,
  verifyTotpCode,
} from '../crypto/cryptoService.js';
import {
  appendAuthEventCsv,
  getUserByUsername,
  logAuditEvent,
  resetAccountSecurityState,
} from '../db/database.js';
import {
  getJwtSecret,
  signAccessToken,
  signLoginChallengeToken,
} from '../middleware/authMiddleware.js';

const router = express.Router();

// Rate-limiting store for 2FA attempts: key -> { count, firstAttemptMs, lockedUntilMs }
const twoFactorAttempts = new Map();
const MAX_2FA_ATTEMPTS = 5;
const WINDOW_MS = 5 * 60 * 1000; // 5 minutes

// Pre-BCrypt Risk Engine store: ip -> { failedEvents: Array<{ username: string, ts: number }> }
const loginRiskByIp = new Map();
const PRE_BCRYPT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes (Lab 3 SOC SHIFT window)
const BRUTE_FORCE_THRESHOLD = 4; // >= 4 failed attempts from 1 IP
const PASSWORD_SPRAY_USER_THRESHOLD = 3; // >= 3 distinct accounts targeted from 1 IP

/**
 * Reset the in-memory 2FA brute-force rate limiter and Pre-BCrypt risk store.
 */
export function resetTwoFactorRateLimit() {
  twoFactorAttempts.clear();
  loginRiskByIp.clear();
}

function resolveClientIp(req) {
  const customIp = req.headers['x-simulated-ip'] || req.body?.simulatedIp;
  if (customIp) {
    return String(customIp).trim();
  }
  return req.ip || '127.0.0.1';
}

function evaluatePreBcryptRisk(ip, targetUsername) {
  const now = Date.now();
  const normalizedUser = String(targetUsername || 'unknown').trim().toLowerCase();
  const record = loginRiskByIp.get(ip) || { failedEvents: [] };
  const recentFailures = record.failedEvents.filter((e) => now - e.ts <= PRE_BCRYPT_WINDOW_MS);
  record.failedEvents = recentFailures;
  loginRiskByIp.set(ip, record);

  const distinctFailedUsers = new Set(recentFailures.map((e) => e.username));
  const projectedDistinctUsers = new Set([...distinctFailedUsers, normalizedUser]);

  if (
    recentFailures.length >= BRUTE_FORCE_THRESHOLD ||
    (recentFailures.length >= PASSWORD_SPRAY_USER_THRESHOLD - 1 &&
      projectedDistinctUsers.size >= PASSWORD_SPRAY_USER_THRESHOLD)
  ) {
    const attackPattern =
      projectedDistinctUsers.size >= PASSWORD_SPRAY_USER_THRESHOLD
        ? 'PASSWORD_SPRAYING'
        : 'BRUTE_FORCE';
    return {
      riskLevel: 'HIGH',
      blockedPreBcrypt: true,
      attackPattern,
      failedCount: recentFailures.length,
      distinctUsersCount: projectedDistinctUsers.size,
    };
  }

  if (recentFailures.length >= 2 || distinctFailedUsers.size >= 2) {
    return {
      riskLevel: 'MEDIUM',
      blockedPreBcrypt: false,
      attackPattern: null,
      failedCount: recentFailures.length,
      distinctUsersCount: projectedDistinctUsers.size,
    };
  }

  return {
    riskLevel: 'LOW',
    blockedPreBcrypt: false,
    attackPattern: null,
    failedCount: recentFailures.length,
    distinctUsersCount: projectedDistinctUsers.size,
  };
}

function recordFailedLoginAttempt(ip, username) {
  const now = Date.now();
  const normalizedUser = String(username || 'unknown').trim().toLowerCase();
  const record = loginRiskByIp.get(ip) || { failedEvents: [] };
  record.failedEvents = record.failedEvents.filter((e) => now - e.ts <= PRE_BCRYPT_WINDOW_MS);
  record.failedEvents.push({ username: normalizedUser, ts: now });
  loginRiskByIp.set(ip, record);
}

function getAttemptKey(username, ip) {
  return `${String(username || 'unknown').toLowerCase()}|${ip || '127.0.0.1'}`;
}

/**
 * POST /api/auth/login
 * Step 1: Pre-BCrypt Risk Assessment (LOW/MEDIUM/HIGH) -> Verify username & password with bcrypt -> return 2FA challenge.
 */
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const ip = resolveClientIp(req);

  if (!username || !password) {
    return res.status(400).json({
      errorCode: 'MISSING_CREDENTIALS',
      message: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.',
    });
  }

  const cleanUsername = String(username).trim();

  // Step 1A: Pre-BCrypt Adaptive Risk Evaluation (protects CPU against Brute-Force & Password Spraying)
  const riskAssessment = evaluatePreBcryptRisk(ip, cleanUsername);
  if (riskAssessment.blockedPreBcrypt) {
    logAuditEvent({
      eventType: 'AUTH_PRE_BCRYPT_BLOCKED',
      severity: 'CRITICAL',
      actor: cleanUsername,
      ipAddress: ip,
      details: {
        riskLevel: riskAssessment.riskLevel,
        attackPattern: riskAssessment.attackPattern,
        failedCountInWindow: riskAssessment.failedCount,
        distinctUsersCount: riskAssessment.distinctUsersCount,
        reason: 'Blocked BEFORE bcrypt.compareSync() to prevent CPU exhaustion & credential stuffing',
      },
    });
    appendAuthEventCsv({
      user: cleanUsername,
      srcIp: ip,
      event: 'pre_bcrypt_blocked',
      asset: 'auth-portal',
      details: `pattern=${riskAssessment.attackPattern};risk=${riskAssessment.riskLevel};fails=${riskAssessment.failedCount};users=${riskAssessment.distinctUsersCount}`,
    });

    return res.status(429).json({
      errorCode: 'PRE_BCRYPT_BLOCKED',
      riskLevel: riskAssessment.riskLevel,
      attackPattern: riskAssessment.attackPattern,
      failedCount: riskAssessment.failedCount,
      distinctUsersCount: riskAssessment.distinctUsersCount,
      message:
        riskAssessment.attackPattern === 'PASSWORD_SPRAYING'
          ? 'CHẶN TRƯỚC BCRYPT (HIGH RISK): Phát hiện tấn công rải mật khẩu (Password Spraying) trên nhiều tài khoản từ cùng một địa chỉ IP!'
          : 'CHẶN TRƯỚC BCRYPT (HIGH RISK): Phát hiện tấn công dò mật khẩu liên tiếp (Brute-force) vượt ngưỡng an toàn!',
    });
  }

  const user = getUserByUsername(cleanUsername);
  if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
    recordFailedLoginAttempt(ip, cleanUsername);
    logAuditEvent({
      eventType: 'AUTH_LOGIN_FAILED',
      severity: 'WARN',
      actor: cleanUsername,
      ipAddress: ip,
      details: {
        reason: 'Invalid username or password',
        riskLevel: riskAssessment.riskLevel,
      },
    });
    appendAuthEventCsv({
      user: cleanUsername,
      srcIp: ip,
      event: 'login_failed',
      asset: 'auth-portal',
      details: `reason=invalid_credentials;risk=${riskAssessment.riskLevel}`,
    });
    return res.status(401).json({
      errorCode: 'INVALID_CREDENTIALS',
      riskLevel: riskAssessment.riskLevel,
      message: 'Tên đăng nhập hoặc mật khẩu không chính xác.',
    });
  }

  const loginChallengeToken = signLoginChallengeToken(user);
  const currentTotp = generateTotpCode(user.totp_secret);

  logAuditEvent({
    eventType: 'AUTH_PASSWORD_VERIFIED',
    severity: 'INFO',
    actor: user.username,
    ipAddress: ip,
    details: {
      riskLevel: riskAssessment.riskLevel,
      message: 'Bước 1 (Mật khẩu) hợp lệ, yêu cầu xác thực 2FA TOTP.',
    },
  });
  appendAuthEventCsv({
    user: user.username,
    srcIp: ip,
    event: 'login_success',
    asset: 'auth-portal',
    details: `stage=password_verified;risk=${riskAssessment.riskLevel}`,
  });

  return res.status(200).json({
    require2FA: true,
    riskLevel: riskAssessment.riskLevel,
    loginChallengeToken,
    demoTotpHint: currentTotp,
    totpSecret: user.totp_secret,
    user: {
      username: user.username,
      displayName: user.display_name,
      role: user.role,
      keyFingerprint: user.key_fingerprint,
      publicKeyPem: user.public_key_pem,
    },
  });
});

/**
 * POST /api/auth/verify-2fa
 * Step 2: Verify 6-digit RFC 6238 TOTP code with brute-force rate-limiting (max 5 failed attempts).
 */
router.post('/verify-2fa', (req, res) => {
  const { username, totpCode, loginChallengeToken } = req.body || {};
  const ip = req.ip || '127.0.0.1';

  let resolvedUsername = username ? String(username).trim() : '';

  if (loginChallengeToken) {
    try {
      const decoded = jwt.verify(String(loginChallengeToken), getJwtSecret());
      if (!resolvedUsername && decoded.username) {
        resolvedUsername = decoded.username;
      }
    } catch {
      return res.status(401).json({
        errorCode: 'INVALID_CHALLENGE_TOKEN',
        message: 'Phiên xác thực bước 1 đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại.',
      });
    }
  }

  if (!resolvedUsername) {
    return res.status(400).json({
      errorCode: 'MISSING_USERNAME',
      message: 'Thiếu thông tin tài khoản xác thực 2FA.',
    });
  }

  const key = getAttemptKey(resolvedUsername, ip);
  const now = Date.now();
  let record = twoFactorAttempts.get(key);

  if (record && now - record.firstAttemptMs > WINDOW_MS) {
    twoFactorAttempts.delete(key);
    record = null;
  }

  if (record && record.count >= MAX_2FA_ATTEMPTS) {
    logAuditEvent({
      eventType: 'AUTH_2FA_BRUTEFORCE_BLOCKED',
      severity: 'CRITICAL',
      actor: resolvedUsername,
      ipAddress: ip,
      details: {
        failedAttempts: record.count,
        message: 'Chặn tạm thời do nhập sai mã 2FA TOTP quá 5 lần liên tiếp.',
      },
    });
    return res.status(429).json({
      errorCode: 'TOO_MANY_ATTEMPTS',
      message: 'Tài khoản bị tạm khóa xác thực 2FA do nhập sai quá 5 lần liên tiếp (Chống Brute-force).',
      retryAfterSeconds: Math.ceil((WINDOW_MS - (now - record.firstAttemptMs)) / 1000),
    });
  }

  const user = getUserByUsername(resolvedUsername);
  if (!user) {
    return res.status(401).json({
      errorCode: 'INVALID_TOTP',
      message: 'Tài khoản hoặc mã xác thực 2FA không hợp lệ.',
    });
  }

  const codeStr = String(totpCode ?? '').trim();
  const isValidTotp = verifyTotpCode(user.totp_secret, codeStr);

  if (!isValidTotp) {
    const updated = record
      ? { count: record.count + 1, firstAttemptMs: record.firstAttemptMs }
      : { count: 1, firstAttemptMs: now };
    twoFactorAttempts.set(key, updated);

    if (updated.count > MAX_2FA_ATTEMPTS) {
      logAuditEvent({
        eventType: 'AUTH_2FA_BRUTEFORCE_BLOCKED',
        severity: 'CRITICAL',
        actor: user.username,
        ipAddress: ip,
        details: {
          failedAttempts: updated.count,
          message: 'Vượt ngưỡng 5 lần thử TOTP sai liên tiếp.',
        },
      });
      return res.status(429).json({
        errorCode: 'TOO_MANY_ATTEMPTS',
        message: 'Tài khoản bị tạm khóa xác thực 2FA do nhập sai quá 5 lần liên tiếp (Chống Brute-force).',
      });
    }

    logAuditEvent({
      eventType: 'AUTH_2FA_FAILED',
      severity: 'WARN',
      actor: user.username,
      ipAddress: ip,
      details: {
        attempt: updated.count,
        maxAttempts: MAX_2FA_ATTEMPTS,
        inputCodeLength: codeStr.length,
      },
    });

    return res.status(401).json({
      errorCode: 'INVALID_TOTP',
      message: `Mã xác thực 2FA TOTP không chính xác hoặc đã hết hạn (Lần thử ${updated.count}/${MAX_2FA_ATTEMPTS}).`,
      remainingAttempts: Math.max(0, MAX_2FA_ATTEMPTS - updated.count),
    });
  }

  // Success -> reset failed counter
  twoFactorAttempts.delete(key);

  const accessToken = signAccessToken(user);

  logAuditEvent({
    eventType: 'AUTH_2FA_SUCCESS',
    severity: 'INFO',
    actor: user.username,
    ipAddress: ip,
    details: {
      message: 'Xác thực 2FA TOTP thành công, đã cấp JWT Access Token.',
      keyFingerprint: user.key_fingerprint,
    },
  });

  return res.status(200).json({
    accessToken,
    tokenType: 'Bearer',
    expiresIn: 3600,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      role: user.role,
      keyFingerprint: user.key_fingerprint,
      publicKeyPem: user.public_key_pem,
    },
  });
});

/**
 * GET /api/auth/demo-totp
 * Helper endpoint for live presentation: returns current 6-digit TOTP and remaining seconds in 30s window.
 */
router.get('/demo-totp', (req, res) => {
  const username = String(req.query.username || 'issuer_admin').trim();
  const user = getUserByUsername(username);
  if (!user) {
    return res.status(404).json({
      errorCode: 'USER_NOT_FOUND',
      message: 'Không tìm thấy tài khoản demo.',
    });
  }

  const nowMs = Date.now();
  const stepSeconds = 30;
  const elapsedInWindow = Math.floor(nowMs / 1000) % stepSeconds;
  const remainingSeconds = stepSeconds - elapsedInWindow;
  const code = generateTotpCode(user.totp_secret, nowMs, stepSeconds);

  return res.status(200).json({
    username: user.username,
    displayName: user.display_name,
    totpCode: code,
    secretBase32: user.totp_secret,
    remainingSeconds,
    stepSeconds,
  });
});

/**
 * GET /api/auth/account-status
 * Return active Issuer account security & session status (for Header & Account Takeover detection).
 */
router.get('/account-status', (req, res) => {
  const username = String(req.query.username || 'issuer_admin').trim();
  const user = getUserByUsername(username);
  if (!user) {
    return res.status(404).json({
      errorCode: 'USER_NOT_FOUND',
      message: 'Không tìm thấy tài khoản.',
    });
  }

  return res.status(200).json({
    username: user.username,
    displayName: user.display_name,
    email: 'daotao@uit.edu.vn',
    accountLocked: Boolean(user.account_locked),
    failedPinAttempts: Number(user.failed_pin_attempts) || 0,
    maxPinAttempts: 3,
    keyFingerprint: user.key_fingerprint,
  });
});

/**
 * POST /api/auth/reset-rate-limit
 * Helper endpoint to reset brute-force lock during live demo or automated testing.
 */
router.post('/reset-rate-limit', (req, res) => {
  resetTwoFactorRateLimit();
  resetAccountSecurityState('issuer_admin');
  return res.status(200).json({
    reset: true,
    message: 'Đã đặt lại bộ đếm giới hạn thử nghiệm 2FA và mở khóa tài khoản.',
  });
});

export default router;
