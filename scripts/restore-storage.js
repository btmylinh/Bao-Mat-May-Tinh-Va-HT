import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const dbPath = path.resolve(process.cwd(), 'data', 'vault.db');
const storageDir = path.resolve(process.cwd(), 'storage');

if (!fs.existsSync(dbPath)) {
  console.error('[Restore] Không tìm thấy cơ sở dữ liệu data/vault.db!');
  process.exit(1);
}

const db = new DatabaseSync(dbPath);
const docs = db
  .prepare(
    'SELECT id, original_filename, storage_filename, backup_encrypted_base64 FROM documents WHERE backup_encrypted_base64 IS NOT NULL'
  )
  .all();

let restoredCount = 0;

for (const doc of docs) {
  const filePath = path.join(storageDir, doc.storage_filename);
  const cleanBuffer = Buffer.from(doc.backup_encrypted_base64, 'base64');
  fs.writeFileSync(filePath, cleanBuffer);
  restoredCount += 1;
  console.log(`+ Đã phục hồi nguyên trạng tệp: ${doc.storage_filename} (${doc.original_filename})`);
}

console.log(`\n=> Phục hồi thành công ${restoredCount} tệp bản mã trong thư mục storage/ về trạng thái ban đầu.`);
