import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { createApp } from './src/app.js';
import { closeDatabase } from './src/db/database.js';

const PORT = Number(process.env.PORT) || 3000;
const HTTPS_PORT = Number(process.env.HTTPS_PORT) || 3443;
const app = createApp();

const certPath = path.resolve(process.cwd(), 'certs', 'server.crt');
const keyPath = path.resolve(process.cwd(), 'certs', 'server.key');

let httpsServer = null;
const httpServer = http.createServer(app).listen(PORT, () => {
  console.log(`[Zero-Trust Vault] HTTP Server running at http://localhost:${PORT}`);
});

if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  try {
    const cert = fs.readFileSync(certPath);
    const key = fs.readFileSync(keyPath);
    httpsServer = https.createServer({ key, cert }, app).listen(HTTPS_PORT, () => {
      console.log(`[Zero-Trust Vault] HTTPS Server running at https://localhost:${HTTPS_PORT}`);
    });
  } catch (err) {
    console.warn(`[Zero-Trust Vault] Không thể khởi chạy HTTPS: ${err.message}`);
  }
}

function gracefulShutdown(signal) {
  console.log(`\n[Zero-Trust Vault] Received ${signal}. Closing servers and SQLite connection...`);
  httpServer.close(() => {
    if (httpsServer) {
      httpsServer.close(() => {
        closeDatabase();
        process.exit(0);
      });
    } else {
      closeDatabase();
      process.exit(0);
    }
  });
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

export default httpServer;
