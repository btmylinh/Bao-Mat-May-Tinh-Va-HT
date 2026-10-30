import { execSync } from 'node:child_process';

const PORTS = [3000, 3443];
const pidsToKill = new Set();

for (const port of PORTS) {
  try {
    const stdout = execSync(`netstat -ano | findstr :${port} | findstr LISTENING`, {
      encoding: 'utf8',
    });
    const lines = stdout.trim().split(/\r?\n/);
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const pid = parts[parts.length - 1];
      if (pid && !isNaN(Number(pid)) && Number(pid) > 0 && Number(pid) !== process.pid) {
        pidsToKill.add(pid);
      }
    }
  } catch {
    // Không có tiến trình nào đang lắng nghe cổng này
  }
}

for (const pid of pidsToKill) {
  try {
    execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' });
    console.log(`[Reset] Đã giải phóng cổng, tắt tiến trình cũ PID: ${pid}`);
  } catch {
    // Bỏ qua nếu tiến trình đã tự kết thúc
  }
}

if (pidsToKill.size === 0) {
  console.log('[Reset] Cổng 3000 và 3443 đã hoàn toàn trống.');
}
