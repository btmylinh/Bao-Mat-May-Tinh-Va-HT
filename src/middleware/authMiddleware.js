import jwt from 'jsonwebtoken';

export const DEFAULT_JWT_SECRET =
  process.env.JWT_SECRET || 'zero-trust-vault-jwt-secret-key-2026-change-in-production';

/**
 * Get the configured JWT secret.
 * @returns {string}
 */
export function getJwtSecret() {
  return process.env.JWT_SECRET || DEFAULT_JWT_SECRET;
}

/**
 * Sign a short-lived step-1 challenge token after password verification (5 minutes).
 * @param {object} user
 * @returns {string}
 */
export function signLoginChallengeToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      stage: '2FA_CHALLENGE',
    },
    getJwtSecret(),
    { expiresIn: '5m' }
  );
}

/**
 * Sign a full session access token after successful 2FA TOTP verification (1 hour).
 * @param {object} user
 * @returns {string}
 */
export function signAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      displayName: user.display_name,
      role: user.role,
      keyFingerprint: user.key_fingerprint,
      twoFactorVerified: true,
    },
    getJwtSecret(),
    { expiresIn: '1h' }
  );
}

/**
 * Express middleware enforcing a valid 2FA-authenticated JWT Bearer token.
 */
export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      errorCode: 'UNAUTHORIZED',
      message: 'Yêu cầu xác thực JWT Bearer token (đã qua 2FA TOTP) để thực hiện thao tác này.',
    });
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    return res.status(401).json({
      errorCode: 'UNAUTHORIZED',
      message: 'Token xác thực trống hoặc không hợp lệ.',
    });
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret());
    if (!decoded.twoFactorVerified) {
      return res.status(401).json({
        errorCode: 'TWO_FACTOR_REQUIRED',
        message: 'Phiên đăng nhập chưa hoàn tất xác thực 2 bước (2FA TOTP).',
      });
    }
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({
      errorCode: 'UNAUTHORIZED',
      message: `Token không hợp lệ hoặc đã hết hạn: ${err.message}`,
    });
  }
}
