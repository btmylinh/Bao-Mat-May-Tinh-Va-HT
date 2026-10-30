import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { initDatabase, listAuditLogs } from './db/database.js';
import { zeroTrustPayloadProtection } from './middleware/payloadProtection.js';
import authRoutes from './routes/authRoutes.js';
import { createDocumentRouter } from './routes/documentRoutes.js';

/**
 * Create and configure the Express application instance for Zero-Trust Document Vault.
 * @param {object} [options]
 * @param {string} [options.dbPath] - Custom SQLite database file path or ':memory:'
 * @param {string} [options.storageDir] - Custom encrypted file storage directory
 * @returns {express.Express}
 */
export function createApp(options = {}) {
  const dbPath =
    options.dbPath || process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'vault.db');
  const storageDir =
    options.storageDir ||
    process.env.STORAGE_DIR ||
    path.resolve(process.cwd(), 'storage');

  initDatabase(dbPath);
  fs.mkdirSync(storageDir, { recursive: true });

  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '30mb' }));
  app.use(express.urlencoded({ extended: true, limit: '30mb' }));

  // Serve SPA static frontend from public/
  const publicDir = path.resolve(process.cwd(), 'public');
  app.use(express.static(publicDir));

  // Healthcheck
  app.get('/api/health', (req, res) => {
    res.status(200).json({
      status: 'ok',
      service: 'Zero-Trust Document Vault API',
      cryptoEngine: 'node:crypto (SHA-256, RSA-2048, AES-256-GCM, TOTP RFC 6238)',
      timestamp: new Date().toISOString(),
    });
  });

  // Zero-Trust Payload & Request Anti-Replay Protection (AES-256-GCM + HMAC-SHA256)
  app.use('/api', zeroTrustPayloadProtection);

  // Security & API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/documents', createDocumentRouter({ storageDir }));

  // Top-level alias for audit logs
  app.get('/api/audit-logs', (req, res) => {
    const limit = Number(req.query.limit) || 50;
    const logs = listAuditLogs(limit);
    return res.status(200).json({ logs });
  });

  // Fallback error handler
  app.use((err, req, res, _next) => {
    const status = err.status || 500;
    res.status(status).json({
      errorCode: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message || 'Đã xảy ra lỗi hệ thống nội bộ.',
    });
  });

  return app;
}

export default createApp;
