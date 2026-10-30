# Cổng Văn Bản & Hồ Sơ Điện Tử (Zero-Trust Document Vault)

> **Đồ án Cuối kỳ — Học phần: Bảo mật Mạng máy tính và Hệ thống**
> **Hướng tiếp cận:** Hệ thống quản lý, phát hành và tra cứu văn bản điện tử đa tầng bảo mật
> **Nguyên lý cốt lõi:** *"Không phải mọi thông tin mà hệ thống nhận được đều đáng tin cậy — Mọi đầu vào, gói tin đường truyền, bản mã lưu trữ, khóa mật mã và phiên truy cập đều phải được kiểm chứng trước khi chấp nhận."*

---

## 1. Giới Thiệu Tổng Quan Dự Án

**Cổng Văn bản & Hồ sơ Điện tử (`Zero-Trust Document Vault`)** là ứng dụng Web nguyên khối tích hợp giữa **Frontend SPA (`Clean Light Mode`)** và **Backend Node.js/Express** vận hành trên một tiến trình duy nhất.

Hệ thống tách bạch rõ ràng giữa **trải nghiệm nghiệp vụ văn phòng** và **nền tảng bảo mật ngầm**:
- **Tầng Phần mềm Nghiệp vụ**: Phục vụ 2 nhóm tác nhân (**Người phát hành** và **Người nhận / Khách**) thực hiện trọn vẹn 7 quy trình nghiệp vụ (`UC01 -> UC07`) từ đăng nhập, tải lên phát hành văn bản (**Công khai `PUBLIC`** hoặc **Nội bộ `PRIVATE`**), quản lý kho hồ sơ, tạo liên kết chia sẻ có thời hạn đến tra cứu, xem trước trực tuyến (`.txt`, `.docx`) và tải tệp gốc về máy.
- **Tầng Bảo mật & Mật mã học**: Vận hành ngầm cơ chế mã hóa phong bì lai (`DEK AES-256-GCM` + `KEK RSA-OAEP-SHA256`), ràng buộc ngữ cảnh `AAD`, chữ ký số `RSA-PSS 2048-bit`, quản lý vòng đời khóa `SPKI SHA-256`, sàng lọc rủi ro trước `BCrypt` (`Pre-BCrypt Risk Triage`) và **Hệ thống Phòng thủ 4 Lớp** ở tầng Giao diện & Đường hầm mã hóa hai chiều (`POST /api/zt-tunnel`).

---

## 2. Bản Đồ Bộ Tài Liệu Dự Án (3 Tệp Tách Bạch)

Bộ tài liệu của dự án được phân tách thành 3 tệp độc lập theo đúng chức năng, không trùng lặp nội dung:

| STT | Tên tệp tài liệu | Phạm vi & Nội dung chuyên trách |
| :--- | :--- | :--- |
| **1** | **[README.md](file:///D:/University/Y4-5%20Bao%20Mat%20May%20Tinh%20Va%20HT/DACK/README.md)** *(Tệp hiện tại)* | Giới thiệu tổng quan dự án, cấu trúc thư mục, yêu cầu môi trường, hướng dẫn cài đặt, khởi chạy (`npm install`, `npm start`, `npm test`) và bảng tài khoản / dữ liệu thử nghiệm. |
| **2** | **[TAI_LIEU_PHAN_MEM.md](file:///D:/University/Y4-5%20Bao%20Mat%20May%20Tinh%20Va%20HT/DACK/TAI_LIEU_PHAN_MEM.md)** | Đặc tả kiến trúc ứng dụng phần mềm, mô hình phân quyền vai trò (`Issuer` / `Recipient` / `Public`), đặc tả chi tiết 7 Use Case nghiệp vụ (`UC01 -> UC07`), thiết kế cơ sở dữ liệu SQLite (`5 bảng`) và hướng dẫn thao tác sử dụng giao diện phần mềm. |
| **3** | **[PHUONG_PHAP_BAO_MAT.md](file:///D:/University/Y4-5%20Bao%20Mat%20May%20Tinh%20Va%20HT/DACK/PHUONG_PHAP_BAO_MAT.md)** | Báo cáo chuyên sâu về phương pháp bảo mật & mật mã học: Giải đáp 5 câu hỏi cốt lõi của đề bài, Mật mã phong bì lai `AES-256-GCM` + `RSA-OAEP-SHA256`, `AAD`, `RSA-PSS 2048-bit`, Hệ thống Phòng thủ 4 Lớp (`Runtime String Obfuscation`, `Strict Tunnel /api/zt-tunnel` + `404 Blackhole`, `Anti-DevTools Shield`, `Anti-Fuzzing HTTP 429`), bộ lệnh kiểm chứng thực tế và Ma trận nghiệm thu `28/28` ca kiểm thử. |

---

## 3. Cấu Trúc Thư Mục Dự Án

```text
DACK/
├── src/
│   ├── crypto/
│   │   └── cryptoService.js       # Lõi mật mã: SHA-256, timingSafeEqual, RSA-PSS, Hybrid DEK/KEK RSA-OAEP, AES-256-GCM + AAD, SPKI Fingerprint, TOTP
│   ├── db/
│   │   └── database.js            # Quản lý SQLite (users, documents, share_links, audit_logs, key_inventory) & đồng bộ CSV/Baseline
│   ├── middleware/
│   │   ├── authMiddleware.js      # Kiểm tra phiên xác thực JWT Bearer Token
│   │   ├── payloadProtection.js   # Đường hầm mã hóa 2 chiều (POST /api/zt-tunnel), Chống Replay HMAC-SHA256, 404 Blackhole & Anti-Fuzzing HTTP 429
│   │   └── uploadMiddleware.js    # Kiểm tra biên kích thước tệp tải lên (0 byte < size <= 10MB)
│   ├── routes/
│   │   ├── authRoutes.js          # Pre-BCrypt Risk Triage (Brute-force/Spraying), BCrypt, 2FA TOTP, Account Status
│   │   └── documentRoutes.js      # Phân loại PUBLIC/PRIVATE, Ký số, Mã hóa phong bì lai, Tra cứu, Tải tệp & Chia sẻ
│   ├── utils/
│   │   └── docExtractor.js        # Trích xuất nội dung xem trước HTML/Text từ tệp Word (.docx)
│   └── app.js                     # Khởi tạo ứng dụng Express nguyên khối
├── public/
│   ├── index.html                 # Giao diện Cổng Văn bản & Hồ sơ Điện tử (Clean Light Mode, 2 Actors, UC01 -> UC07)
│   ├── styles.css                 # Bảng màu sáng chuẩn ứng dụng hành chính/doanh nghiệp
│   └── app.js                     # Xử lý luồng nghiệp vụ, Obfuscation XOR 0x5A, Anti-DevTools Shield & protectedFetch() qua /api/zt-tunnel
├── scripts/
│   ├── sha-inspector.js           # Công cụ CLI đối chiếu SHA-256, Hash Baseline Drift, Hybrid Envelope & Key Inventory
│   └── soc-detector.js            # Công cụ CLI phân tích data/auth_events.csv theo MITRE ATT&CK T1110 (SOC SHIFT)
├── tests/
│   ├── security.test.js           # Bộ kiểm thử tự động 28 bài (1 Unit Crypto + 27 ca TC01 -> TC27)
│   └── ui-e2e-capture.js          # Kịch bản kiểm thử giao diện tự động & chụp ảnh nghiệm thu (1440x900)
├── data/
│   ├── vault.db                   # Cơ sở dữ liệu SQLite cục bộ
│   ├── key_inventory.csv          # Danh mục vòng đời khóa KEK & SPKI SHA-256 Fingerprint
│   ├── auth_events.csv            # Nhật ký sự kiện xác thực chuẩn SOC SHIFT
│   └── hash_baseline.txt          # Bản ghi đối chiếu mã băm SHA-256 gốc (Baseline)
├── storage/                       # Kho lưu trữ tệp nhị phân đã mã hóa AES-256-GCM (*.enc)
├── README.md                      # Tổng quan dự án, cấu trúc thư mục & hướng dẫn cài đặt / khởi chạy
├── TAI_LIEU_PHAN_MEM.md           # Tài liệu đặc tả phần mềm, phân quyền, 7 Use Case, CSDL & hướng dẫn sử dụng
├── PHUONG_PHAP_BAO_MAT.md         # Tài liệu chuyên sâu phương pháp bảo mật, mật mã học, 4 lớp phòng thủ & kiểm chứng
├── server.js                      # Điểm khởi chạy máy chủ tại cổng 3000
└── package.json                   # Cấu hình scripts và dependencies
```

---

## 4. Yêu Cầu Môi Trường & Ngăn Xếp Công Nghệ

- **Môi trường thực thi**: **Node.js `v22.5.0` trở lên** (khuyến nghị `v24.x` LTS để sử dụng trực tiếp các mô-đun tích hợp sẵn `node:sqlite`, `node:crypto` và `node:test` mà không cần trình biên dịch C++ ngoài).
- **Hệ điều hành hỗ trợ**: Windows, Linux, macOS.
- **Thư viện phụ thuộc (`package.json`)**:
  - `express` (`4.22.3`): Khung máy chủ Web và định tuyến đường hầm.
  - `bcryptjs` (`3.0.3`): Băm và xác thực mật khẩu cán bộ phát hành.
  - `jsonwebtoken` (`9.0.3`): Cấp phát và kiểm tra phiên làm việc sau khi xác thực 2FA.
  - `multer` (`2.5.0`): Xử lý bộ nhớ đệm cho tệp tải lên.
  - `mammoth` (`1.8.0`): Trích xuất nội dung xem trước từ tệp tài liệu Word (`.docx`).
  - `dotenv` (`18.0.9`): Quản lý biến môi trường cấu hình.

---

## 5. Hướng Dẫn Cài Đặt, Khởi Chạy & Kiểm Thử

### 5.1. Cài đặt và Khởi chạy Máy chủ Web

```bash
# 1. Cài đặt các gói thư viện phụ thuộc
npm install

# 2. Khởi chạy máy chủ Cổng Văn bản & Hồ sơ Điện tử tại cổng 3000
npm start
```

Sau khi khởi chạy, mở trình duyệt truy cập địa chỉ: **`http://localhost:3000`**

### 5.2. Chạy Bộ Kiểm Thử Tự Động & Công Cụ Giám Sát CLI

```bash
# Chạy trọn bộ 28 ca kiểm thử bảo mật tự động (1 Unit Crypto + 27 ca TC01 -> TC27)
npm test

# Chạy công cụ CLI kiểm tra SHA-256 Baseline Drift, Phong bì lai DEK/KEK & Key Inventory
npm run tool:sha

# Chạy công cụ CLI phân tích nhật ký SOC (data/auth_events.csv) theo MITRE ATT&CK T1110
npm run tool:soc
```

---

## 6. Bảng Tài Khoản Thử Nghiệm & Hồ Sơ Văn Bản Mặc Định

### 6.1. Thông tin Tài khoản Cán bộ Phát hành (`UC01` & `UC02`)

| Thông số | Giá trị mặc định | Mục đích sử dụng |
| :--- | :--- | :--- |
| **Tên đăng nhập (`Username`)** | `issuer_admin` | Đăng nhập vào Cổng Quản trị Người phát hành (`UC01`) |
| **Mật khẩu (`Password`)** | `Admin@123` | Xác thực mật khẩu bước 1 (trước khi xác thực 2FA TOTP) |
| **Khóa bí mật 2FA (`TOTP Secret`)** | `JBSWY3DPEHPK3PXP` | Sinh mã OTP 6 chữ số theo chuẩn RFC 6238 (chu kỳ 30 giây) |
| **Mã xác nhận lưu trữ (`Signing PIN`)** | `UIT-SIGN-2026` | Xác nhận cấp 2 khi phát hành và ký số văn bản mới (`UC02`) |
| **Đơn vị ban hành hiển thị** | `Phòng Đào tạo - ĐH CNTT (Issuer)` | Tên cơ quan gắn kèm chữ ký số `RSA-PSS` |
