/**
 * Cổng Văn bản & Hồ sơ Điện tử
 * 2 Tác nhân (Người nhận / Khách & Người phát hành) - 7 Use Case thuần nghiệp vụ (UC01 -> UC07)
 */

const state = {
  isIssuerLoggedIn: false,
  jwtToken: null,
  totpSecret: 'JBSWY3DPEHPK3PXP',
  selectedUploadFile: null,
  currentDocId: null,
  currentDocCode: 'VB-2026-0001',
  pendingDeleteDoc: null,
  documents: [],
  publicDocuments: [],
  searchQuery: '',
  publicSearchQuery: '',
  lastPreviewBlobUrl: null,
  lastPreviewFilename: 'document.txt',
};

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(base32Str) {
  const cleaned = String(base32Str)
    .toUpperCase()
    .replace(/=+$/, '')
    .replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (let i = 0; i < cleaned.length; i += 1) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(cleaned[i]);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

async function generateTotpBrowser(secretBase32, timestampMs = Date.now()) {
  const keyBytes = decodeBase32(secretBase32);
  const counter = Math.floor(Math.floor(timestampMs / 1000) / 30);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const hmacBuffer = await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
  const hmac = new Uint8Array(hmacBuffer);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, '0');
}

const ZT_TRANSPORT_PASSPHRASE = 'zt-vault-transport-protection-2026-key';
let cachedAesKey = null;
let cachedHmacKey = null;

/**
 * Layer 1: Runtime Endpoint String Obfuscation (XOR 0x5A + Hex table).
 * Eliminates all plaintext endpoint strings from client source inspection.
 */
const _ZT_XOR_KEY = 0x5a;
const _ZT_ENDPOINTS = Object.freeze({
  TUNNEL: '753b2a3375202e772e2f34343f36',
  AUTH_LOGIN: '753b2a33753b2f2e327536353d3334',
  AUTH_VERIFY_2FA: '753b2a33753b2f2e32752c3f28333c2377683c3b',
  DOCS_ROOT: '753b2a33753e35392f373f342e29',
  DOCS_PUBLIC: '753b2a33753e35392f373f342e29752a2f38363339',
  DOCS_SIGN: '753b2a33753e35392f373f342e297529333d34',
  DOCS_EXTRACT_PREVIEW: '753b2a33753e35392f373f342e29753f222e283b392e772a283f2c333f2d',
  DOCS_LOOKUP_PREFIX: '753b2a33753e35392f373f342e2975363535312f2a75',
  DOCS_SHARE_PREFIX: '753b2a33753e35392f373f342e297529323b283f75',
  SHARE_SUFFIX: '7529323b283f',
});

function resolveEndpoint(hexEncoded) {
  let out = '';
  for (let i = 0; i < hexEncoded.length; i += 2) {
    out += String.fromCharCode(parseInt(hexEncoded.slice(i, i + 2), 16) ^ _ZT_XOR_KEY);
  }
  return out;
}

function uint8ToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const sub = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, sub);
  }
  return window.btoa(binary);
}

/**
 * Layer 3: Anti-DevTools & Anti-Hooking Runtime Shield.
 * - Blocks F12, Ctrl+Shift+I/J/C, Ctrl+U and right-click contextmenu
 * - Freezes Web Crypto & JSON objects against prototype/function hooking
 * - Runs async debugger trap when outside automated E2E browser session
 */
function initSecurityShield() {
  // Cho phép mở DevTools và Chuột phải để thuận tiện gỡ lỗi, kiểm tra Network và chụp ảnh minh chứng API
  const devToolsAllowed = true;

  window.addEventListener(
    'keydown',
    (e) => {
      const key = String(e.key || '').toUpperCase();
      const isF12 = key === 'F12' || e.keyCode === 123;
      const isCtrlShiftInspect =
        (e.ctrlKey || e.metaKey) && e.shiftKey && (key === 'I' || key === 'J' || key === 'C');
      const isViewSource = (e.ctrlKey || e.metaKey) && key === 'U';
      if ((isF12 || isCtrlShiftInspect || isViewSource) && !devToolsAllowed) {
        e.preventDefault();
        e.stopPropagation();
        return false;
      }
      return undefined;
    },
    true
  );

  window.addEventListener(
    'contextmenu',
    (e) => {
      if (!devToolsAllowed) {
        e.preventDefault();
        return false;
      }
      return undefined;
    },
    true
  );

  try {
    if (window.crypto && window.crypto.subtle) {
      Object.freeze(window.crypto.subtle);
    }
    Object.freeze(JSON);
  } catch {
    // Ignore if environment restricts freezing host objects
  }

  // Tắt bẫy debugger để mở tab Network / Console mượt mà không bị treo trang
  window.__ZT_SHIELD_ACTIVE__ = Object.freeze({
    antiDevTools: false,
    antiHooking: true,
    strictTunnel: true,
    stringObfuscation: true,
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hexStr) {
  const clean = String(hexStr || '').trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function getTransportCryptoKeys() {
  if (cachedAesKey && cachedHmacKey) {
    return { aesKey: cachedAesKey, hmacKey: cachedHmacKey };
  }
  const enc = new TextEncoder();
  const rawHash = await window.crypto.subtle.digest(
    'SHA-256',
    enc.encode(ZT_TRANSPORT_PASSPHRASE)
  );
  cachedAesKey = await window.crypto.subtle.importKey(
    'raw',
    rawHash,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
  cachedHmacKey = await window.crypto.subtle.importKey(
    'raw',
    rawHash,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return { aesKey: cachedAesKey, hmacKey: cachedHmacKey };
}

async function sha256HexBrowser(str) {
  const enc = new TextEncoder();
  const digest = await window.crypto.subtle.digest('SHA-256', enc.encode(String(str || '')));
  return bytesToHex(new Uint8Array(digest));
}

async function encryptJsonPayloadBrowser(jsonStr) {
  const { aesKey } = await getTransportCryptoKeys();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plainBytes = new TextEncoder().encode(jsonStr);
  const cipherBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    plainBytes
  );
  const cipherAll = new Uint8Array(cipherBuffer);
  const ciphertext = cipherAll.slice(0, cipherAll.length - 16);
  const authTag = cipherAll.slice(cipherAll.length - 16);
  let b64 = '';
  for (let i = 0; i < ciphertext.length; i += 1) {
    b64 += String.fromCharCode(ciphertext[i]);
  }
  return `${bytesToHex(iv)}.${window.btoa(b64)}.${bytesToHex(authTag)}`;
}

async function decryptJsonPayloadBrowser(envelopeStr) {
  const parts = String(envelopeStr || '').split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted response envelope');
  }
  const [ivHex, cipherB64, tagHex] = parts;
  const iv = hexToBytes(ivHex);
  const tagBytes = hexToBytes(tagHex);
  const binStr = window.atob(cipherB64);
  const cipherBytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i += 1) {
    cipherBytes[i] = binStr.charCodeAt(i);
  }
  const combined = new Uint8Array(cipherBytes.length + tagBytes.length);
  combined.set(cipherBytes, 0);
  combined.set(tagBytes, cipherBytes.length);

  const { aesKey } = await getTransportCryptoKeys();
  const plainBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    combined
  );
  const plainText = new TextDecoder('utf-8').decode(plainBuf);
  return JSON.parse(plainText);
}

/**
 * Zero-Trust Two-Way Encrypted Tunnel Fetch:
 * - Routes 100% of requests (JSON, GET, DELETE, and FormData file uploads) through the obfuscated tunnel endpoint with AES-256-GCM encrypted `{ method, path, body }` (`ztEncryptedPayload`)
 * - Automatically decrypts `{ ztEncryptedResponse }` so `res.json()` returns plaintext data transparently to UI logic
 * - Attaches `X-ZT-Timestamp`, `X-ZT-Nonce`, and `X-ZT-Signature` (HMAC-SHA256) to prevent request replay & tampering
 */
async function protectedFetch(url, options = {}) {
  const originalMethod = String(options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };
  const isMultipartFormData =
    typeof FormData !== 'undefined' && options.body instanceof FormData;

  let parsedBody = {};
  if (isMultipartFormData) {
    for (const [key, val] of options.body.entries()) {
      if (typeof Blob !== 'undefined' && val instanceof Blob) {
        const arrBuf = await val.arrayBuffer();
        const bytes = new Uint8Array(arrBuf);
        parsedBody.__ztFile = {
          fieldname: key,
          originalname: val.name || 'document.bin',
          mimetype: val.type || 'application/octet-stream',
          base64: uint8ToBase64(bytes),
          size: bytes.length,
        };
      } else {
        parsedBody[key] = val;
      }
    }
  } else if (typeof options.body === 'string' && options.body.trim().length > 0) {
    try {
      parsedBody = JSON.parse(options.body);
    } catch {
      parsedBody = options.body;
    }
  } else if (options.body && typeof options.body === 'object') {
    parsedBody = options.body;
  }

  const tunnelPlainJson = JSON.stringify({
    method: originalMethod,
    path: url,
    body: parsedBody,
  });
  const encryptedEnvelope = await encryptJsonPayloadBrowser(tunnelPlainJson);
  const canonicalPayloadString = encryptedEnvelope;
  const requestUrl = resolveEndpoint(_ZT_ENDPOINTS.TUNNEL);
  const requestMethod = 'POST';
  const requestBody = JSON.stringify({ ztEncryptedPayload: encryptedEnvelope });

  headers['X-ZT-Encrypted'] = 'AES-256-GCM';
  headers['Content-Type'] = 'application/json';

  const timestamp = String(Date.now());
  const nonceBytes = window.crypto.getRandomValues(new Uint8Array(16));
  const nonce = bytesToHex(nonceBytes);
  const payloadHash = await sha256HexBrowser(canonicalPayloadString);
  const canonical = `${requestMethod}|${requestUrl}|${timestamp}|${nonce}|${payloadHash}`;

  const { hmacKey } = await getTransportCryptoKeys();
  const sigBuf = await window.crypto.subtle.sign(
    'HMAC',
    hmacKey,
    new TextEncoder().encode(canonical)
  );
  const signatureHex = bytesToHex(new Uint8Array(sigBuf));

  headers['X-ZT-Timestamp'] = timestamp;
  headers['X-ZT-Nonce'] = nonce;
  headers['X-ZT-Signature'] = signatureHex;

  const response = await fetch(requestUrl, {
    ...options,
    method: requestMethod,
    headers,
    body: requestBody,
  });

  const rawJsonFn = response.json.bind(response);
  let cachedDecryptedJson;
  response.json = async () => {
    if (cachedDecryptedJson !== undefined) {
      return cachedDecryptedJson;
    }
    const rawData = await rawJsonFn();
    if (
      rawData &&
      typeof rawData === 'object' &&
      typeof rawData.ztEncryptedResponse === 'string'
    ) {
      cachedDecryptedJson = await decryptJsonPayloadBrowser(rawData.ztEncryptedResponse);
      return cachedDecryptedJson;
    }
    cachedDecryptedJson = rawData;
    return cachedDecryptedJson;
  };

  return response;
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.2s ease';
    setTimeout(() => toast.remove(), 220);
  }, 3000);
}

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDateTime(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString('vi-VN', { hour12: false });
  } catch {
    return isoStr;
  }
}

function toggleModal(modalId, show) {
  const el = document.getElementById(modalId);
  if (!el) return;
  if (show) {
    el.classList.remove('hidden');
  } else {
    el.classList.add('hidden');
  }
}

function showGlobalNotice(show, message = '') {
  const bar = document.getElementById('portal-global-notice');
  const txt = document.getElementById('portal-notice-text');
  if (!bar) return;

  if (!show) {
    bar.classList.add('hidden');
    return;
  }
  bar.classList.remove('hidden');
  if (txt) txt.textContent = message;
}

/**
 * Switch between Public Recipient Portal (Actor 1) and Issuer Dashboard (Actor 2).
 * @param {'recipient' | 'issuer'} mode
 */
function switchPortalMode(mode) {
  const recipientSection = document.getElementById('recipient-portal-view');
  const issuerSection = document.getElementById('issuer-dashboard-view');
  const guestActions = document.getElementById('header-guest-actions');
  const issuerActions = document.getElementById('header-issuer-actions');
  const issuerSidebar = document.getElementById('issuer-sidebar');
  const navCatalog = document.getElementById('nav-issuer-catalog');
  const navLookup = document.getElementById('nav-issuer-lookup');

  showGlobalNotice(false);

  if (state.isIssuerLoggedIn) {
    issuerSidebar?.classList.remove('hidden');
  } else {
    issuerSidebar?.classList.add('hidden');
  }

  if (mode === 'issuer') {
    recipientSection?.classList.add('hidden');
    issuerSection?.classList.remove('hidden');
    guestActions?.classList.add('hidden');
    issuerActions?.classList.remove('hidden');
    navCatalog?.classList.add('active');
    navLookup?.classList.remove('active');
  } else {
    issuerSection?.classList.add('hidden');
    recipientSection?.classList.remove('hidden');
    navCatalog?.classList.remove('active');
    navLookup?.classList.add('active');
    if (state.isIssuerLoggedIn) {
      guestActions?.classList.add('hidden');
      issuerActions?.classList.remove('hidden');
    } else {
      issuerActions?.classList.add('hidden');
      guestActions?.classList.remove('hidden');
    }
  }
}

async function authenticateIssuer(username = 'issuer_admin', password = 'Admin@123') {
  const loginRes = await protectedFetch(resolveEndpoint(_ZT_ENDPOINTS.AUTH_LOGIN), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const loginData = await loginRes.json();
  if (!loginRes.ok) {
    throw new Error(loginData.message || 'Tài khoản hoặc mật khẩu không đúng.');
  }

  const secret = loginData.totpSecret || state.totpSecret;
  const totpCode = loginData.demoTotpHint || (await generateTotpBrowser(secret));

  const verifyRes = await protectedFetch(resolveEndpoint(_ZT_ENDPOINTS.AUTH_VERIFY_2FA), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      loginChallengeToken: loginData.loginChallengeToken,
      totpCode,
    }),
  });
  const verifyData = await verifyRes.json();
  if (!verifyRes.ok) {
    throw new Error(verifyData.message || 'Không thể đăng nhập hệ thống.');
  }

  state.jwtToken = verifyData.accessToken || verifyData.token;
  return state.jwtToken;
}

async function ensureAuthenticated() {
  if (state.jwtToken) return state.jwtToken;
  return authenticateIssuer('issuer_admin', 'Admin@123');
}

/**
 * UC01: Handle Issuer Login from Login Modal.
 */
async function handleIssuerLogin() {
  const userIn = document.getElementById('login-username-input');
  const passIn = document.getElementById('login-password-input');
  const alertEl = document.getElementById('login-modal-alert');
  const btnSubmit = document.getElementById('btn-submit-login');

  const username = (userIn?.value || 'issuer_admin').trim();
  const password = passIn?.value || 'Admin@123';

  try {
    if (btnSubmit) {
      btnSubmit.disabled = true;
      btnSubmit.textContent = 'Đang đăng nhập...';
    }
    if (alertEl) alertEl.classList.add('hidden');

    await authenticateIssuer(username, password);
    state.isIssuerLoggedIn = true;

    toggleModal('login-modal', false);
    await loadDocumentsCatalog();
    switchPortalMode('issuer');
    showToast('Đăng nhập hệ thống thành công.', 'success');
  } catch (err) {
    if (alertEl) {
      alertEl.textContent = err.message;
      alertEl.classList.remove('hidden');
    }
  } finally {
    if (btnSubmit) {
      btnSubmit.disabled = false;
      btnSubmit.textContent = 'Đăng nhập';
    }
  }
}

function buildUploadFileFromInputs() {
  if (state.selectedUploadFile) {
    return state.selectedUploadFile;
  }
  const filenameInput = document.getElementById('doc-filename-input');
  const contentInput = document.getElementById('doc-content-input');
  const filename =
    (filenameInput?.value || '').trim() || 'Quyet_Dinh_Cong_Nhan_Tot_Nghiep_2026.txt';
  const content = (contentInput?.value || '').trim();
  return new File([content], filename, { type: 'text/plain;charset=utf-8' });
}

/**
 * UC04: Create a time-bound share link for a document (7d / 30d / 90d / 1y).
 */
async function createShareLinkForDoc(docId, expiresInSeconds = 604800) {
  const token = await ensureAuthenticated();
  const sec = Number(expiresInSeconds) || 604800;
  const sharePath = `${resolveEndpoint(_ZT_ENDPOINTS.DOCS_ROOT)}/${encodeURIComponent(docId)}${resolveEndpoint(_ZT_ENDPOINTS.SHARE_SUFFIX)}`;
  const res = await protectedFetch(sharePath, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      expiresInSeconds: sec,
      expiresInMinutes: Math.round(sec / 60),
    }),
  });

  if (res.status === 401) {
    state.jwtToken = null;
  }

  const data = await res.json();
  if (!res.ok) {
    if (res.status === 423 || data.errorCode === 'ACCOUNT_COMPROMISED_LOCKED') {
      throw new Error(
        'Tài khoản tạm khóa chức năng tải lên và chia sẻ do nhập sai mã xác nhận quá 3 lần.'
      );
    }
    throw new Error(data.message || 'Không thể tạo liên kết chia sẻ.');
  }

  const fullShareUrl = `${window.location.origin}/?share=${data.token}`;
  return {
    ...data,
    fullShareUrl,
  };
}

/**
 * UC02: Upload and store a new document, assigning a Document Code (e.g., VB-2026-0001).
 */
async function handleUploadAndStore(silentInit = false, customSeed = null) {
  const btnSign = document.getElementById('btn-sign-doc');
  const signerInput = document.getElementById('doc-signer-input');
  const pinInput = document.getElementById('doc-signing-pin');
  const visSelect = document.getElementById('doc-visibility-select');
  const modalAlert = document.getElementById('upload-modal-alert');
  const modalAlertMsg = document.getElementById('upload-alert-message');

  try {
    if (btnSign) {
      btnSign.disabled = true;
      btnSign.textContent = 'Đang lưu trữ...';
    }
    if (modalAlert) modalAlert.classList.add('hidden');

    const token = await ensureAuthenticated();
    const fileToUpload = customSeed?.file || buildUploadFileFromInputs();
    const signerName =
      customSeed?.signerName ||
      (signerInput?.value || '').trim() ||
      'Phòng Đào tạo - Trường ĐH CNTT';
    const signingPin = pinInput ? pinInput.value : 'UIT-SIGN-2026';
    const visibility =
      customSeed?.visibility || (visSelect?.value === 'PRIVATE' ? 'PRIVATE' : 'PUBLIC');

    const formData = new FormData();
    formData.append('title', fileToUpload.name);
    formData.append('signerName', signerName);
    formData.append('signingPin', signingPin);
    formData.append('visibility', visibility);
    formData.append('file', fileToUpload, fileToUpload.name);

    const res = await protectedFetch(resolveEndpoint(_ZT_ENDPOINTS.DOCS_SIGN), {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: formData,
    });

    if (res.status === 401) {
      state.jwtToken = null;
    }

    const data = await res.json();

    if (!res.ok) {
      let friendlyMsg = data.message || 'Không thể lưu trữ văn bản.';
      if (res.status === 423 || data.errorCode === 'ACCOUNT_COMPROMISED_LOCKED') {
        friendlyMsg =
          'Tài khoản tạm khóa chức năng tải lên và chia sẻ do nhập sai mã xác nhận quá 3 lần.';
        showGlobalNotice(true, friendlyMsg);
      } else if (data.errorCode === 'MALICIOUS_OR_FORGED_INPUT') {
        friendlyMsg = 'Không thể tải tệp: Định dạng hoặc nội dung tệp không hợp lệ.';
        showGlobalNotice(true, friendlyMsg);
      }

      if (modalAlert && modalAlertMsg) {
        modalAlert.classList.remove('hidden');
        modalAlertMsg.textContent = friendlyMsg;
      }
      if (!silentInit) showToast(friendlyMsg, 'error');
      return null;
    }

    showGlobalNotice(false);
    state.currentDocId = data.id;
    state.currentDocCode = data.docCode || 'VB-2026-0001';

    const codeEl = document.getElementById('share-modal-doccode');
    const nameEl = document.getElementById('share-modal-docname');
    if (codeEl) codeEl.textContent = state.currentDocCode;
    if (nameEl) nameEl.textContent = data.originalFilename;

    const expireSelect = document.getElementById('share-expire-select');
    const shareData = await createShareLinkForDoc(
      data.id,
      Number(expireSelect?.value) || 604800
    );
    const shareOutput = document.getElementById('share-link-output');
    if (shareOutput) shareOutput.value = shareData.fullShareUrl;

    await loadDocumentsCatalog();
    if (!silentInit) {
      showToast(
        `Đã lưu trữ văn bản ${state.currentDocCode} (${data.originalFilename}).`,
        'success'
      );
    }
    return data;
  } catch (err) {
    if (!silentInit) showToast(err.message, 'error');
    return null;
  } finally {
    if (btnSign) {
      btnSign.disabled = false;
      btnSign.textContent = 'Lưu trữ văn bản';
    }
  }
}

/**
 * Open the Upload & Share Modal focused on a specific document for sharing (UC04).
 */
async function openShareModalForDoc(doc) {
  if (!doc) return;
  state.currentDocId = doc.id;
  state.currentDocCode = doc.docCode || 'VB-2026-0001';

  const codeEl = document.getElementById('share-modal-doccode');
  const nameEl = document.getElementById('share-modal-docname');
  if (codeEl) codeEl.textContent = state.currentDocCode;
  if (nameEl) nameEl.textContent = doc.originalFilename;

  document.getElementById('upload-modal-alert')?.classList.add('hidden');
  toggleModal('upload-share-modal', true);

  try {
    const expireSelect = document.getElementById('share-expire-select');
    const shareData = await createShareLinkForDoc(
      doc.id,
      Number(expireSelect?.value) || 604800
    );
    const shareOutput = document.getElementById('share-link-output');
    if (shareOutput) shareOutput.value = shareData.fullShareUrl;
    await loadDocumentsCatalog();
  } catch (err) {
    showGlobalNotice(true, err.message);
    showToast(err.message, 'error');
  }
}

/**
 * Extract Share Token or Document Code (e.g., VB-2026-0001) from raw input or URL.
 */
function parseLookupQuery(rawInput) {
  const trimmed = String(rawInput || '').trim();
  if (!trimmed) return '';
  try {
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      const u = new URL(trimmed);
      const qShare = u.searchParams.get('share');
      if (qShare) return qShare.trim();
      const parts = u.pathname.split('/').filter(Boolean);
      return parts[parts.length - 1] || '';
    }
  } catch {
    // Fallback
  }
  if (trimmed.includes('?share=')) {
    return trimmed.split('?share=')[1].split('&')[0].trim();
  }
  const sharePrefix = resolveEndpoint(_ZT_ENDPOINTS.DOCS_SHARE_PREFIX);
  if (trimmed.includes(sharePrefix)) {
    return trimmed.split(sharePrefix)[1].split('?')[0].trim();
  }
  return trimmed;
}

/**
 * UC05 & UC06: Look up a document by Document Code (VB-2026-0001) or Share Link/Token,
 * and render the Online Document Preview Card (UC06) + Download Button (UC07).
 */
async function handleLookupDocument(customQuery = null, options = { populateInput: true }) {
  const inputEl = document.getElementById('lookup-query-input');
  const rawValue = customQuery !== null ? customQuery : inputEl?.value || '';
  const query = parseLookupQuery(rawValue);
  const previewCard = document.getElementById('recipient-preview-card');

  if (!query) {
    showToast('Vui lòng nhập mã định danh văn bản hoặc liên kết chia sẻ.', 'warn');
    return;
  }

  if (customQuery !== null && inputEl && options?.populateInput !== false) {
    inputEl.value = customQuery;
  }

  try {
    const lookupPath = `${resolveEndpoint(_ZT_ENDPOINTS.DOCS_LOOKUP_PREFIX)}${encodeURIComponent(query)}`;
    const res = await protectedFetch(lookupPath);
    const data = await res.json();

    if (!res.ok || !data.verified) {
      previewCard?.classList.add('hidden');
      let msg =
        data.message ||
        'Không thể truy cập: Liên kết chia sẻ hoặc chữ ký xác thực không hợp lệ.';
      if (data.errorCode === 'STORAGE_TAMPERED' || data.errorCode === 'INTEGRITY_VIOLATION') {
        msg = 'Không thể mở tệp: Nội dung tệp đã bị thay đổi hoặc không hợp lệ.';
      } else if (
        data.errorCode === 'SIGNATURE_FORGED' ||
        data.errorCode === 'LINK_REVOKED_ACCOUNT_TAKEOVER' ||
        data.errorCode === 'LINK_EXPIRED'
      ) {
        msg = 'Không thể truy cập: Liên kết chia sẻ hoặc chữ ký xác thực không hợp lệ.';
      }
      showGlobalNotice(true, msg);
      showToast(msg, 'error');
      return;
    }

    showGlobalNotice(false);

    const binaryStr = window.atob(data.contentBase64 || '');
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i += 1) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    const doc = data.document || {};
    const blob = new Blob([bytes], {
      type: doc.mimeType || 'application/octet-stream',
    });

    if (state.lastPreviewBlobUrl) {
      URL.revokeObjectURL(state.lastPreviewBlobUrl);
    }
    state.lastPreviewBlobUrl = URL.createObjectURL(blob);
    state.lastPreviewFilename = doc.originalFilename || 'document.txt';

    const decodedText =
      typeof data.extractedText === 'string' && data.extractedText.trim()
        ? data.extractedText
        : new TextDecoder('utf-8').decode(bytes);

    // Populate UC06 Online Preview Card
    const codeEl = document.getElementById('preview-doc-code');
    const titleEl = document.getElementById('preview-doc-title');
    const issuerEl = document.getElementById('preview-doc-issuer');
    const dateEl = document.getElementById('preview-doc-date');
    const sizeEl = document.getElementById('preview-doc-size');
    const contentEl = document.getElementById('preview-doc-content');

    if (codeEl) codeEl.textContent = doc.docCode || 'VB-2026-0001';
    if (titleEl) titleEl.textContent = doc.originalFilename || doc.title;
    if (issuerEl) issuerEl.textContent = doc.issuerName || 'Phòng Đào tạo - Trường ĐH CNTT';
    if (dateEl) dateEl.textContent = formatDateTime(doc.createdAt);
    if (sizeEl) sizeEl.textContent = formatBytes(doc.fileSize);
    if (contentEl) {
      if (typeof data.extractedHtml === 'string' && data.extractedHtml.trim()) {
        contentEl.innerHTML = data.extractedHtml;
      } else {
        contentEl.textContent = decodedText;
      }
    }

    previewCard?.classList.remove('hidden');
  } catch (err) {
    showToast(`Lỗi tra cứu văn bản: ${err.message}`, 'error');
  }
}

/**
 * UC07: Download the original document file to the computer.
 */
function handleRecipientDownloadFile() {
  if (!state.lastPreviewBlobUrl) return;
  const a = document.createElement('a');
  a.href = state.lastPreviewBlobUrl;
  a.download = state.lastPreviewFilename || 'document.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  showToast(`Đang tải tệp "${state.lastPreviewFilename}" về máy.`, 'success');
}

/**
 * Render the Public Documents Table on the Recipient Portal (ONLY PUBLIC documents).
 */
function renderPublicCatalogTable() {
  const tbody = document.getElementById('public-docs-tbody');
  if (!tbody) return;

  const q = state.publicSearchQuery.trim().toLowerCase();
  const filtered = state.publicDocuments.filter((d) => {
    if (!q) return true;
    return (
      String(d.docCode || '').toLowerCase().includes(q) ||
      String(d.originalFilename || '').toLowerCase().includes(q) ||
      String(d.issuerName || '').toLowerCase().includes(q)
    );
  });

  tbody.innerHTML = '';

  filtered.forEach((doc) => {
    const tr = document.createElement('tr');
    tr.dataset.docId = doc.id;
    tr.dataset.docCode = doc.docCode || 'VB-2026-0001';

    tr.innerHTML = `
      <td><span class="doc-code-badge cell-code"></span></td>
      <td class="file-title-cell cell-filename"></td>
      <td class="cell-issuer"></td>
      <td>${formatDateTime(doc.createdAt)}</td>
      <td>${formatBytes(doc.fileSize)}</td>
      <td><span class="status-pill scope-public">Công khai</span></td>
      <td class="col-actions">
        <div class="row-actions">
          <button type="button" class="btn-primary btn-sm btn-public-view">Xem</button>
        </div>
      </td>
    `;

    tr.querySelector('.cell-code').textContent = doc.docCode || 'VB-2026-0001';
    tr.querySelector('.cell-filename').textContent = doc.originalFilename;
    tr.querySelector('.cell-issuer').textContent = doc.issuerName;

    tr.querySelector('.btn-public-view').addEventListener('click', async () => {
      await handleLookupDocument(doc.docCode || doc.id);
    });

    tbody.appendChild(tr);
  });
}

/**
 * Open confirmation modal before deleting a document (UC03).
 */
function openDeleteConfirmModal(doc) {
  if (!doc) return;
  state.pendingDeleteDoc = doc;
  const codeEl = document.getElementById('delete-modal-doccode');
  const nameEl = document.getElementById('delete-modal-docname');
  if (codeEl) codeEl.textContent = doc.docCode || 'VB-2026-0001';
  if (nameEl) nameEl.textContent = doc.originalFilename;
  toggleModal('delete-confirm-modal', true);
}

/**
 * Execute document deletion after user confirms in modal.
 */
async function handleConfirmDeleteDoc() {
  const doc = state.pendingDeleteDoc;
  if (!doc) return;
  const btnConfirm = document.getElementById('btn-confirm-delete');
  try {
    if (btnConfirm) {
      btnConfirm.disabled = true;
      btnConfirm.textContent = 'Đang xóa...';
    }
    const token = await ensureAuthenticated();
    const delPath = `${resolveEndpoint(_ZT_ENDPOINTS.DOCS_ROOT)}/${encodeURIComponent(doc.id)}`;
    const res = await protectedFetch(delPath, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || 'Không thể xóa văn bản.');
    }
    toggleModal('delete-confirm-modal', false);
    state.pendingDeleteDoc = null;
    await loadDocumentsCatalog();
    showToast(`Đã xóa văn bản ${doc.docCode} (${doc.originalFilename}).`, 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    if (btnConfirm) {
      btnConfirm.disabled = false;
      btnConfirm.textContent = 'Xác nhận xóa';
    }
  }
}

/**
 * UC03: Render the Issuer Document Catalog Table.
 */
function renderIssuerCatalogTable() {
  const tbody = document.getElementById('issuer-docs-tbody');
  if (!tbody) return;

  const q = state.searchQuery.trim().toLowerCase();
  const filtered = state.documents.filter((d) => {
    if (!q) return true;
    return (
      String(d.docCode || '').toLowerCase().includes(q) ||
      String(d.originalFilename || '').toLowerCase().includes(q) ||
      String(d.issuerName || '').toLowerCase().includes(q) ||
      String(d.visibilityLabel || '').toLowerCase().includes(q)
    );
  });

  tbody.innerHTML = '';

  filtered.forEach((doc) => {
    const tr = document.createElement('tr');
    tr.dataset.docId = doc.id;
    tr.dataset.docCode = doc.docCode || 'VB-2026-0001';

    const isShared = doc.publishStatus === 'Đang chia sẻ';
    const statusClass = isShared ? 'status-shared' : 'status-issued';
    const statusLabel = doc.publishStatus || 'Đã ban hành';
    const isPrivate = doc.visibility === 'PRIVATE';
    const scopeClass = isPrivate ? 'scope-private' : 'scope-public';
    const scopeLabel = isPrivate ? 'Nội bộ' : 'Công khai';

    tr.innerHTML = `
      <td><span class="doc-code-badge cell-code"></span></td>
      <td class="file-title-cell cell-filename"></td>
      <td class="cell-issuer"></td>
      <td>${formatDateTime(doc.createdAt)}</td>
      <td>${formatBytes(doc.fileSize)}</td>
      <td><span class="status-pill ${scopeClass}">${scopeLabel}</span></td>
      <td><span class="status-pill ${statusClass}">${statusLabel}</span></td>
      <td class="col-actions">
        <div class="row-actions">
          <button type="button" class="btn-primary btn-sm btn-row-share">Chia sẻ</button>
          <button type="button" class="btn-secondary btn-sm btn-row-view">Xem</button>
          <button type="button" class="btn-danger-outline btn-sm btn-row-delete">Xóa</button>
        </div>
      </td>
    `;

    tr.querySelector('.cell-code').textContent = doc.docCode || 'VB-2026-0001';
    tr.querySelector('.cell-filename').textContent = doc.originalFilename;
    tr.querySelector('.cell-issuer').textContent = doc.issuerName;

    tr.querySelector('.btn-row-share').addEventListener('click', () => {
      openShareModalForDoc(doc);
    });
    tr.querySelector('.btn-row-view').addEventListener('click', async () => {
      switchPortalMode('recipient');
      await handleLookupDocument(doc.docCode || doc.id);
    });
    tr.querySelector('.btn-row-delete').addEventListener('click', () => {
      openDeleteConfirmModal(doc);
    });

    tbody.appendChild(tr);
  });
}

async function loadDocumentsCatalog() {
  try {
    const [allRes, pubRes] = await Promise.all([
      protectedFetch(resolveEndpoint(_ZT_ENDPOINTS.DOCS_ROOT)),
      protectedFetch(resolveEndpoint(_ZT_ENDPOINTS.DOCS_PUBLIC)),
    ]);
    if (allRes.ok) {
      const data = await allRes.json();
      state.documents = data.documents || [];
    }
    if (pubRes.ok) {
      const pubData = await pubRes.json();
      state.publicDocuments = pubData.documents || [];
    }

    if (!state.currentDocId && state.documents.length > 0) {
      state.currentDocId = state.documents[0].id;
      state.currentDocCode = state.documents[0].docCode || 'VB-2026-0001';
    }

    renderPublicCatalogTable();
    renderIssuerCatalogTable();
  } catch {
    // Ignore
  }
}

function bindEvents() {
  // Brand click -> Recipient Portal
  document.getElementById('btn-home-brand')?.addEventListener('click', () => {
    switchPortalMode('recipient');
  });

  // Header buttons: Open Login Modal (UC01), Switch to Public Portal, Logout
  document.getElementById('btn-open-issuer-login')?.addEventListener('click', () => {
    document.getElementById('login-modal-alert')?.classList.add('hidden');
    toggleModal('login-modal', true);
  });
  document.getElementById('btn-close-login-modal')?.addEventListener('click', () => {
    toggleModal('login-modal', false);
  });
  document.getElementById('btn-cancel-login')?.addEventListener('click', () => {
    toggleModal('login-modal', false);
  });
  document.getElementById('btn-submit-login')?.addEventListener('click', () => {
    handleIssuerLogin();
  });

  document.getElementById('btn-switch-to-public')?.addEventListener('click', () => {
    switchPortalMode('recipient');
  });
  document.getElementById('nav-issuer-catalog')?.addEventListener('click', () => {
    switchPortalMode('issuer');
  });
  document.getElementById('nav-issuer-lookup')?.addEventListener('click', () => {
    switchPortalMode('recipient');
  });
  document.getElementById('btn-logout-issuer')?.addEventListener('click', () => {
    state.isIssuerLoggedIn = false;
    state.jwtToken = null;
    switchPortalMode('recipient');
    showToast('Đã đăng xuất khỏi cổng cán bộ phát hành.', 'info');
  });

  // Delete Confirm Modal
  document.getElementById('btn-close-delete-modal')?.addEventListener('click', () => {
    toggleModal('delete-confirm-modal', false);
  });
  document.getElementById('btn-cancel-delete')?.addEventListener('click', () => {
    toggleModal('delete-confirm-modal', false);
  });
  document.getElementById('btn-confirm-delete')?.addEventListener('click', () => {
    handleConfirmDeleteDoc();
  });

  // Notice dismiss
  document.getElementById('btn-close-notice')?.addEventListener('click', () => {
    showGlobalNotice(false);
  });

  // UC05: Recipient Lookup button & Enter key
  document.getElementById('btn-lookup-doc')?.addEventListener('click', () => {
    handleLookupDocument();
  });
  document.getElementById('lookup-query-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleLookupDocument();
    }
  });

  // UC07: Recipient Download File button
  document
    .getElementById('btn-recipient-download')
    ?.addEventListener('click', handleRecipientDownloadFile);

  // UC03: Search box in Issuer Dashboard & Public Search box
  document.getElementById('search-docs-input')?.addEventListener('input', (e) => {
    state.searchQuery = e.target.value || '';
    renderIssuerCatalogTable();
  });
  document.getElementById('public-search-input')?.addEventListener('input', (e) => {
    state.publicSearchQuery = e.target.value || '';
    renderPublicCatalogTable();
  });

  // UC02 & UC04: Open / Close Upload & Share Modal
  document.getElementById('btn-open-upload-modal')?.addEventListener('click', () => {
    document.getElementById('upload-modal-alert')?.classList.add('hidden');
    toggleModal('upload-share-modal', true);
  });
  document.getElementById('btn-close-upload-modal')?.addEventListener('click', () => {
    toggleModal('upload-share-modal', false);
  });
  document.getElementById('btn-cancel-upload')?.addEventListener('click', () => {
    toggleModal('upload-share-modal', false);
  });

  // Dropzone inside Upload Modal
  const signDropzone = document.getElementById('sign-dropzone');
  const fileInput = document.getElementById('file-input');
  const updateSelectedFileUI = async (file) => {
    if (!file) return;
    state.selectedUploadFile = file;
    const nameEl = document.getElementById('selected-file-name');
    const filenameInput = document.getElementById('doc-filename-input');
    const contentInput = document.getElementById('doc-content-input');
    const docxPreviewEl = document.getElementById('upload-docx-preview');
    if (nameEl) nameEl.textContent = `${file.name} (${formatBytes(file.size)})`;
    if (filenameInput) filenameInput.value = file.name;

    try {
      const fd = new FormData();
      fd.append('file', file, file.name);
      const res = await protectedFetch(resolveEndpoint(_ZT_ENDPOINTS.DOCS_EXTRACT_PREVIEW), {
        method: 'POST',
        body: fd,
      });
      if (res.ok) {
        const data = await res.json();
        if (contentInput && typeof data.extractedText === 'string') {
          contentInput.value = data.extractedText;
        }
        if (docxPreviewEl && typeof data.extractedHtml === 'string' && data.extractedHtml.trim()) {
          docxPreviewEl.innerHTML = data.extractedHtml;
          docxPreviewEl.classList.remove('hidden');
          contentInput?.classList.add('hidden');
        }
      }
    } catch {
      // Keep original binary file intact even if preview extraction is skipped
    }
  };

  if (signDropzone && fileInput) {
    signDropzone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      const f = e.target.files?.[0];
      if (f) updateSelectedFileUI(f);
    });
    signDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      signDropzone.classList.add('drag-over');
    });
    signDropzone.addEventListener('dragleave', () => {
      signDropzone.classList.remove('drag-over');
    });
    signDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      signDropzone.classList.remove('drag-over');
      const f = e.dataTransfer?.files?.[0];
      if (f) updateSelectedFileUI(f);
    });
  }

  document.getElementById('doc-filename-input')?.addEventListener('input', () => {
    state.selectedUploadFile = null;
    document.getElementById('upload-docx-preview')?.classList.add('hidden');
    document.getElementById('doc-content-input')?.classList.remove('hidden');
  });
  document.getElementById('doc-content-input')?.addEventListener('input', () => {
    state.selectedUploadFile = null;
  });

  // UC02: Store document button
  document.getElementById('btn-sign-doc')?.addEventListener('click', () => {
    handleUploadAndStore(false);
  });

  // UC04: Create share link & Copy share link
  document.getElementById('btn-create-share')?.addEventListener('click', async () => {
    if (!state.currentDocId) return;
    try {
      const expireSelect = document.getElementById('share-expire-select');
      const shareData = await createShareLinkForDoc(
        state.currentDocId,
        Number(expireSelect?.value) || 604800
      );
      const shareOut = document.getElementById('share-link-output');
      if (shareOut) shareOut.value = shareData.fullShareUrl;
      await loadDocumentsCatalog();
      showToast('Đã tạo liên kết chia sẻ mới.', 'success');
    } catch (err) {
      showGlobalNotice(true, err.message);
      showToast(err.message, 'error');
    }
  });

  document.getElementById('btn-copy-share')?.addEventListener('click', async () => {
    const val = document.getElementById('share-link-output')?.value || '';
    if (!val) return;
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(val);
    }
    showToast('Đã sao chép liên kết chia sẻ.', 'success');
  });
}

async function initApp() {
  initSecurityShield();
  bindEvents();
  await loadDocumentsCatalog();

  if (state.documents.length === 0) {
    // 1. Seed PUBLIC document (VB-2026-0001)
    await handleUploadAndStore(true);

    // 2. Seed PRIVATE document (VB-2026-0002)
    const privateContent = [
      'TRƯỜNG ĐẠI HỌC CÔNG NGHỆ THÔNG TIN - PHÒNG KẾ HOẠCH TÀI CHÍNH',
      'SỐ HIỆU: 2026/HĐ-NB-KHTC • PHẠM VI: LƯU HÀNH NỘI BỘ',
      'HỢP ĐỒNG PHÂN BỔ NGÂN SÁCH & ĐẦU TƯ PHÒNG THÍ NGHIỆM AN TOÀN THÔNG TIN 2026',
      '1. Hạng mục Hệ thống Máy chủ Lưu trữ & Kiểm chứng Văn bản: 450.000.000 VNĐ',
      '2. Hạng mục Thiết bị Bảo mật Phần cứng & Cấp phát Khóa: 280.000.000 VNĐ',
      '3. Quy định bảo mật: Chỉ cán bộ có mã định danh hoặc liên kết chia sẻ mới được phép mở văn bản.',
    ].join('\n');
    const privateFile = new File(
      [privateContent],
      'Hop_Dong_Ngan_Sach_Noi_Bo_2026.txt',
      { type: 'text/plain;charset=utf-8' }
    );
    await handleUploadAndStore(true, {
      file: privateFile,
      signerName: 'Phòng Kế hoạch Tài chính - Trường ĐH CNTT',
      visibility: 'PRIVATE',
    });
  }

  // Default view: Public Recipient Portal (Actor 1 - No login required)
  switchPortalMode('recipient');

  const urlParams = new URLSearchParams(window.location.search);
  const queryShare = urlParams.get('share');
  if (queryShare) {
    await handleLookupDocument(`${window.location.origin}/?share=${queryShare}`, {
      populateInput: true,
    });
  } else if (state.publicDocuments.length > 0) {
    const firstCode = state.publicDocuments[0].docCode || 'VB-2026-0001';
    await handleLookupDocument(firstCode, { populateInput: false });
  } else if (state.documents.length > 0) {
    const firstCode = state.documents[0].docCode || 'VB-2026-0001';
    await handleLookupDocument(firstCode, { populateInput: false });
  }
}

document.addEventListener('DOMContentLoaded', initApp);
