import fs from 'node:fs';
import path from 'node:path';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const AUTH_CSV_PATH = path.join(DATA_DIR, 'auth_events.csv');
const BASELINE_PATH = path.join(DATA_DIR, 'hash_baseline.txt');
const WINDOW_MINUTES = 10;
const WINDOW_MS = WINDOW_MINUTES * 60 * 1000;
const BRUTE_FORCE_THRESHOLD = 4;
const PASSWORD_SPRAY_USER_THRESHOLD = 3;

function ensureSampleAuthEventsIfEmpty() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(AUTH_CSV_PATH)) {
    fs.writeFileSync(
      AUTH_CSV_PATH,
      'timestamp,user,src_ip,event,asset,details\n',
      'utf8'
    );
  }
  const content = fs.readFileSync(AUTH_CSV_PATH, 'utf8').trim();
  const lines = content.split(/\r?\n/).filter(Boolean);
  if (lines.length <= 1) {
    const baseMs = Date.now() - 4 * 60 * 1000;
    const sampleRows = [
      `${new Date(baseMs).toISOString()},issuer_admin,185.220.101.42,login_failed,auth-portal,reason=invalid_credentials;risk=LOW`,
      `${new Date(baseMs + 15000).toISOString()},issuer_admin,185.220.101.42,login_failed,auth-portal,reason=invalid_credentials;risk=LOW`,
      `${new Date(baseMs + 30000).toISOString()},issuer_admin,185.220.101.42,login_failed,auth-portal,reason=invalid_credentials;risk=MEDIUM`,
      `${new Date(baseMs + 45000).toISOString()},issuer_admin,185.220.101.42,login_failed,auth-portal,reason=invalid_credentials;risk=MEDIUM`,
      `${new Date(baseMs + 60000).toISOString()},issuer_admin,185.220.101.42,pre_bcrypt_blocked,auth-portal,pattern=BRUTE_FORCE;risk=HIGH;fails=4;users=1`,
      `${new Date(baseMs + 90000).toISOString()},ke_toan_01,203.0.113.88,login_failed,auth-portal,reason=invalid_credentials;risk=LOW`,
      `${new Date(baseMs + 105000).toISOString()},van_thu_02,203.0.113.88,login_failed,auth-portal,reason=invalid_credentials;risk=LOW`,
      `${new Date(baseMs + 120000).toISOString()},dao_tao_03,203.0.113.88,pre_bcrypt_blocked,auth-portal,pattern=PASSWORD_SPRAYING;risk=HIGH;fails=2;users=3`,
    ];
    fs.appendFileSync(AUTH_CSV_PATH, `${sampleRows.join('\n')}\n`, 'utf8');
  }
}

function parseCsvEvents() {
  ensureSampleAuthEventsIfEmpty();
  const raw = fs.readFileSync(AUTH_CSV_PATH, 'utf8');
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const events = [];

  for (let i = 1; i < lines.length; i += 1) {
    const parts = lines[i].split(',');
    if (parts.length < 6) continue;
    const [timestamp, user, srcIp, event, asset, ...rest] = parts;
    const tsMs = new Date(timestamp).getTime();
    if (Number.isNaN(tsMs)) continue;
    events.push({
      timestamp,
      tsMs,
      user: user.trim(),
      srcIp: srcIp.trim(),
      event: event.trim(),
      asset: asset.trim(),
      details: rest.join(',').trim(),
    });
  }
  return events.sort((a, b) => a.tsMs - b.tsMs);
}

function runSocDetection() {
  console.log('========================================================================');
  console.log(' [SOC SHIFT DETECTOR - LAB 3] PHAN TICH LOG XAC THUC & MITRE ATT&CK');
  console.log('========================================================================');
  console.log(` -> Nguon log CSV : ${AUTH_CSV_PATH}`);
  console.log(` -> Khung cua so  : ${WINDOW_MINUTES} phut (Brute-force >= ${BRUTE_FORCE_THRESHOLD} fails | Spraying >= ${PASSWORD_SPRAY_USER_THRESHOLD} users)`);
  console.log('------------------------------------------------------------------------');

  const events = parseCsvEvents();
  console.log(` -> Tong so su kien ghi nhan: ${events.length}`);

  const byIp = new Map();
  for (const ev of events) {
    if (!byIp.has(ev.srcIp)) {
      byIp.set(ev.srcIp, []);
    }
    byIp.get(ev.srcIp).push(ev);
  }

  const alerts = [];

  for (const [srcIp, ipEvents] of byIp.entries()) {
    for (let i = 0; i < ipEvents.length; i += 1) {
      const startMs = ipEvents[i].tsMs;
      const windowEvents = ipEvents.filter(
        (e) => e.tsMs >= startMs && e.tsMs <= startMs + WINDOW_MS
      );

      const failedEvents = windowEvents.filter(
        (e) => e.event === 'login_failed' || e.event === 'pre_bcrypt_blocked'
      );
      const distinctFailedUsers = new Set(failedEvents.map((e) => e.user));
      const preBcryptBlocks = windowEvents.filter((e) => e.event === 'pre_bcrypt_blocked');
      const successAfterFail = windowEvents.find(
        (e) =>
          e.event === 'login_success' &&
          failedEvents.filter((f) => f.tsMs < e.tsMs).length >= 3
      );

      if (failedEvents.length >= BRUTE_FORCE_THRESHOLD && distinctFailedUsers.size === 1) {
        alerts.push({
          type: 'BRUTE_FORCE_ATTACK',
          mitre: 'T1110.001 (Password Guessing)',
          severity: 'HIGH',
          srcIp,
          targetUsers: [...distinctFailedUsers],
          failedCount: failedEvents.length,
          preBcryptBlocked: preBcryptBlocks.length > 0,
        });
        break;
      }

      if (distinctFailedUsers.size >= PASSWORD_SPRAY_USER_THRESHOLD) {
        alerts.push({
          type: 'PASSWORD_SPRAYING_ATTACK',
          mitre: 'T1110.003 (Password Spraying)',
          severity: 'HIGH',
          srcIp,
          targetUsers: [...distinctFailedUsers],
          failedCount: failedEvents.length,
          preBcryptBlocked: preBcryptBlocks.length > 0,
        });
        break;
      }

      if (successAfterFail) {
        alerts.push({
          type: 'SUSPICIOUS_LOGIN_SUCCESS_AFTER_FAILURES',
          mitre: 'T1078 / T1110 (Valid Accounts after Brute-force)',
          severity: 'CRITICAL',
          srcIp,
          targetUsers: [successAfterFail.user],
          failedCount: failedEvents.length,
          preBcryptBlocked: preBcryptBlocks.length > 0,
        });
        break;
      }
    }
  }

  if (alerts.length === 0) {
    console.log('\n [OK] Khong phat hien hanh vi Brute-force hay Password Spraying bat thuong.');
  } else {
    console.log(`\n [ALERT] PHAT HIEN ${alerts.length} CANH BAO TAN CONG XAC THUC:`);
    alerts.forEach((a, idx) => {
      console.log(`\n   #${idx + 1} [${a.severity}] ${a.type} — MITRE ATT&CK: ${a.mitre}`);
      console.log(`      - Nguon IP tan cong   : ${a.srcIp}`);
      console.log(`      - Tai khoan bi nham   : ${a.targetUsers.join(', ')}`);
      console.log(`      - So lan thu that bai : ${a.failedCount} lan / ${WINDOW_MINUTES} phut`);
      console.log(
        `      - Pre-BCrypt Shield   : ${
          a.preBcryptBlocked
            ? 'DA CHAN TRUOC BCRYPT (HTTP 429 PRE_BCRYPT_BLOCKED)'
            : 'Ghi nhan canh bao SOC'
        }`
      );
    });
  }

  if (fs.existsSync(BASELINE_PATH)) {
    const baselineLines = fs
      .readFileSync(BASELINE_PATH, 'utf8')
      .split(/\r?\n/)
      .filter((l) => l.trim() && !l.startsWith('#'));
    console.log('\n------------------------------------------------------------------------');
    console.log(` [HASH BASELINE SNAPSHOT] (${BASELINE_PATH}) — ${baselineLines.length} ban ghi:`);
    for (const line of baselineLines) {
      console.log(`   ${line}`);
    }
  }
  console.log('========================================================================');
}

runSocDetection();
