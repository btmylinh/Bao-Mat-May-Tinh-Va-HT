import 'dotenv/config';
import { createApp } from './src/app.js';
import { closeDatabase } from './src/db/database.js';

const PORT = Number(process.env.PORT) || 3000;
const app = createApp();

const server = app.listen(PORT, () => {
  console.log(`[Zero-Trust Vault] Server running at http://localhost:${PORT}`);
});

function gracefulShutdown(signal) {
  console.log(`\n[Zero-Trust Vault] Received ${signal}. Closing server and SQLite connection...`);
  server.close(() => {
    closeDatabase();
    process.exit(0);
  });
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

export default server;
