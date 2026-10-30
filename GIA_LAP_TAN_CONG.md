# Hướng Dẫn Giả Lập Tấn Công & Kiểm Chứng An Toàn Hệ Thống

> **Tài liệu Hướng dẫn Thực nghiệm Phòng thủ — Sử dụng Máy ảo VMware Windows 10 & Công cụ Bên thứ 3**
> *(Học phần: Bảo mật Mạng máy tính và Hệ thống — Đồ án: Cổng Văn bản & Hồ sơ Điện tử Zero-Trust Document Vault)*
> *(Xem thêm: [README.md](file:///D:/University/Y4-5%20Bao%20Mat%20May%20Tinh%20Va%20HT/DACK/README.md) | [TAI_LIEU_PHAN_MEM.md](file:///D:/University/Y4-5%20Bao%20Mat%20May%20Tinh%20Va%20HT/DACK/TAI_LIEU_PHAN_MEM.md) | [PHUONG_PHAP_BAO_MAT.md](file:///D:/University/Y4-5%20Bao%20Mat%20May%20Tinh%20Va%20HT/DACK/PHUONG_PHAP_BAO_MAT.md))*

---

## 1. Mô Hình Mạng & Kiến Trúc Thực Nghiệm

Mô hình thực nghiệm được thiết kế theo chuẩn Zero-Trust: **Không tin tưởng bất kỳ thiết bị hay yêu cầu nào đến từ bên ngoài mạng cục bộ**.

```text
+------------------------------------------+        Mạng ảo VMware (NAT / Bridged)        +------------------------------------------+
|          MÁY ẢO VMWARE WIN 10            |                                              |                 MÁY THẬT                 |
|       (Attacker / External Client)       | -------------------------------------------> |         (Zero-Trust Vault Server)        |
|                                          |                                              |                                          |
|  * Postman / cURL (Tấn công API)         |          Gói tin HTTP Port 3000              |  * Node.js Server (Express Port 3000)    |
|  * Trình duyệt Web độc lập (F12)         |                                              |  * SQLite Database (data/vault.db)       |
|  * HxD Hex Editor (Sửa byte bản mã)      |                                              |  * Kho mã hóa AES-256-GCM (storage/)     |
|  * Địa chỉ IP: DHCP từ VMware VMnet8     |                                              |  * Địa chỉ IP Host: 192.168.101.1        |
+------------------------------------------+                                              +------------------------------------------+
```

---

## 2. Các Bước Thiết Lập Kết Nối Giữa Máy Ảo & Máy Thật

### Bước 2.1. Cấu hình Card mạng VMware
1. Trên phần mềm VMware Workstation, mở máy ảo Windows 10 -> vào mục **Virtual Machine Settings** -> **Network Adapter**.
2. Chọn chế độ mạng:
   - **NAT (Khuyến nghị nhất — VMnet8):** Máy thật có địa chỉ IP mặc định là `192.168.101.1`.
   - **Bridged (Replicate physical network state):** Máy ảo nhận cùng dải IP Wi-Fi với máy thật (ví dụ `192.168.2.x`).

### Bước 2.2. Khởi chạy Server và Mở Cổng Tường lửa trên Máy thật
1. Khởi chạy máy chủ tại thư mục dự án trên máy thật:
   ```powershell
   npm start
   ```
   *(Hệ thống hiển thị: `[Zero-Trust Vault] Server running at http://localhost:3000`)*.
2. Mở cổng 3000 trên Windows Firewall của máy thật (nếu máy ảo chưa truy cập được):
   ```powershell
   # Chạy lệnh PowerShell với quyền Administrator trên máy thật:
   New-NetFirewallRule -DisplayName "ZeroTrustVault-3000" -Direction Inbound -LocalPort 3000 -Protocol TCP -Action Allow
   ```

### Bước 2.3. Kiểm tra thông mạng từ Máy ảo VMware Windows 10
Mở cửa sổ Command Prompt (CMD) trên máy ảo Windows 10 và kiểm tra kết nối:
```cmd
ping 192.168.101.1
```
*(Nếu thấy kết quả `Reply from 192.168.101.1: bytes=32 time<1ms TTL=128` là kết nối thành công).*

---

## 3. Danh Mục Công Cụ Bên Thứ 3 Chuẩn Bị Trên Máy Ảo

1. **Trình duyệt Web (Google Chrome hoặc Microsoft Edge có sẵn trên Windows 10)**: Dùng để thao tác giao diện, mở DevTools soi gói tin mạng và gửi yêu cầu xác thực.
2. **Công cụ cURL (có sẵn trong CMD/PowerShell của Windows 10) hoặc Postman**: Dùng để gửi trực tiếp các gói tin REST API thô ngoài luồng đường hầm.
3. **Phần mềm chỉnh sửa mã nhị phân HxD Hex Editor**: Phần mềm miễn phí siêu nhẹ dùng để sửa đổi 1 byte tệp bản mã lưu trữ trên đĩa nhằm kiểm chứng tính toàn vẹn (tải tại: `mh-nexus.de/en/hxd/` hoặc dùng Notepad).

---

## 4. Bảng 6 Kịch Bản Giả Lập Tấn Công Thực Tế

| Mã ca | Loại hình tấn công | Công cụ bên thứ 3 | Hành động tấn công | Phản hồi của hệ thống | Trạng thái |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AT01** | Gọi trực tiếp REST API ngoài luồng | Postman / cURL | Gửi yêu cầu GET/POST thẳng vào các endpoint nghiệp vụ `/api/...` | `HTTP 404 Not Found` (404 Blackhole che giấu toàn bộ API) | **CHẶN ĐỨNG** |
| **AT02** | Dò quét từ điển API (API Fuzzing) | cURL / Script | Gửi liên tiếp trên 10 yêu cầu rác vào cổng máy chủ trong 60 giây | `HTTP 429 ANTI_FUZZING_BLOCKED` (Tự động khóa IP máy ảo) | **CHẶN ĐỨNG** |
| **AT03** | Tấn công vét cạn mật khẩu (Brute-force) | Trình duyệt Web | Nhập sai mật khẩu cán bộ phát hành 4 lần liên tiếp từ IP máy ảo | `HTTP 429 PRE_BCRYPT_BLOCKED` (Pre-BCrypt chặn sớm, bảo vệ CPU) | **CHẶN ĐỨNG** |
| **AT04** | Can thiệp byte tệp lưu trữ (1-Byte Tampering) | HxD Hex Editor | Sửa đổi 1 byte trong tệp mã hóa `storage/*.enc` trên ổ đĩa | `HTTP 422 STORAGE_TAMPERED` (Cảnh báo Đỏ, từ chối giải mã) | **CHẶN ĐỨNG** |
| **AT05** | Tải lên tệp thực thi độc hại hoặc mã XSS | Trình duyệt Web | Tải lên tệp `.exe`, `.bat` hoặc tên chứa `<script>alert(1)</script>` | `HTTP 400 MALICIOUS_OR_FORGED_INPUT` (Từ chối ký & lưu trữ) | **CHẶN ĐỨNG** |
| **AT06** | Mở liên kết chia sẻ quá hạn (Expired Link) | Trình duyệt Web | Truy cập liên kết chia sẻ có token đã hết hạn hiệu lực | `HTTP 403 LINK_EXPIRED` (Từ chối cấp quyền truy cập) | **CHẶN ĐỨNG** |

---

## 5. Hướng Dẫn Chi Tiết Từng Kịch Bản Giả Lập Tấn Công

### Kịch Bản 1: Gọi trực tiếp REST API ngoài luồng (Kiểm chứng 404 Blackhole)

* **Bối cảnh tấn công**: Kẻ tấn công trên máy ảo dùng Postman hoặc cURL cố tình gọi trực tiếp vào các đường dẫn API phổ biến để thu thập dữ liệu trái phép mà không qua giao diện Web.
* **Thao tác thực hiện trên máy ảo (CMD/PowerShell)**:
  ```cmd
  curl -i http://192.168.101.1:3000/api/documents
  curl -i http://192.168.101.1:3000/api/documents/public
  curl -i -X POST http://192.168.101.1:3000/api/auth/login
  ```
* **Kết quả quan sát**:
  - Máy chủ trả về đồng nhất: `HTTP/1.1 404 Not Found`.
  - Toàn bộ bề mặt API nghiệp vụ được giấu kín hoàn toàn. Hệ thống chỉ tiếp nhận các yêu cầu được đóng gói và mã hóa hai chiều gửi qua `POST /api/zt-tunnel`.

---

### Kịch Bản 2: Dò quét từ điển API (API Fuzzing) — Kích hoạt Tự động Khóa IP

* **Bối cảnh tấn công**: Kẻ tấn công chạy công cụ dò quét tự động (như `ffuf`, `gobuster` hoặc vòng lặp cURL) để tìm kiếm các đường dẫn ẩn trên máy chủ.
* **Thao tác thực hiện trên máy ảo (PowerShell)**:
  ```powershell
  # Chạy vòng lặp gửi 10 yêu cầu quét đường dẫn rác:
  1..10 | ForEach-Object {
      curl.exe -s http://192.168.101.1:3000/api/fuzz-probe-$_ | Out-Null
      Write-Host "Đã gửi request quét thăm dò lần $_"
  }
  ```
* **Thực hiện yêu cầu thứ 11**:
  ```cmd
  curl -i http://192.168.101.1:3000/api/documents
  ```
* **Kết quả quan sát**:
  - Máy chủ phản hồi mã lỗi: **`HTTP/1.1 429 Too Many Requests`**.
  - Nội dung phản hồi:
    ```json
    {
      "errorCode": "ANTI_FUZZING_BLOCKED",
      "message": "CẢNH BÁO BẢO MẬT: Phát hiện hành vi dò quét tự động từ địa chỉ IP của bạn. IP đã bị tạm khóa tự động!"
    }
    ```
  - Địa chỉ IP của máy ảo bị đưa vào danh sách phong tỏa trong 60 giây, chặn đứng hoàn toàn công cụ dò quét.

---

### Kịch Bản 3: Tấn công vét cạn mật khẩu (Brute-force) — Kích hoạt Pre-BCrypt Risk Triage

* **Bối cảnh tấn công**: Kẻ tấn công cố tình thử sai mật khẩu liên tiếp nhằm dò mật khẩu quản trị hoặc làm nghẽn CPU máy chủ bằng hàm băm nặng `BCrypt`.
* **Thao tác thực hiện trên máy ảo**:
  1. Mở trình duyệt Web trên máy ảo truy cập: `http://192.168.101.1:3000`.
  2. Bấm nút **Chuyển sang Cổng phát hành** để mở màn hình đăng nhập.
  3. Nhập tài khoản: `issuer_admin`.
  4. Cố tình nhập sai mật khẩu 4 lần liên tiếp (ví dụ: `123456`, `admin123`, `password`, `sai_pass`).
* **Kết quả quan sát**:
  - Tại lần thử thứ 4, hệ thống không gọi hàm `BCrypt` mà kích hoạt bộ lọc sớm **Pre-BCrypt Risk Triage**:
  - Phản hồi mã lỗi: **`HTTP 429 PRE_BCRYPT_BLOCKED`**.
  - Thông báo đỏ hiển thị trên giao diện: *Phát hiện tấn công vét cạn mật khẩu từ IP của bạn! Hệ thống chặn sớm để bảo vệ tài nguyên.*
* **Kiểm chứng trên máy thật**:
  Mở terminal máy thật chạy công cụ SOC:
  ```powershell
  npm run tool:soc
  ```
  -> Màn hình máy thật in ra cảnh báo phát hiện tấn công theo chuẩn **MITRE ATT&CK T1110** (Brute Force) ghi nhận chính xác địa chỉ IP của máy ảo vừa bị phong tỏa.

---

### Kịch Bản 4: Can thiệp dữ liệu trên đĩa (Storage Tampering 1-byte)

* **Bối cảnh tấn công**: Kẻ tấn công nội gián hoặc hacker xâm nhập vào máy chủ và chỉnh sửa trực tiếp 1 byte dữ liệu của tệp bản mã lưu trữ trên ổ đĩa.
* **Thao tác thực hiện**:
  1. Trên **Máy thật**, mở thư mục `storage/` chứa các tệp mã hóa nhị phân `.enc`.
  2. Chọn một tệp bất kỳ (ví dụ `897fb0e3-d5c0-482a-bdf8-0921264b8481.enc` tương ứng với văn bản `VB-2026-0002`).
  3. Mở tệp bằng phần mềm **HxD Hex Editor** (hoặc Notepad), sửa duy nhất **1 ký tự bất kỳ** trong tệp và bấm **Save (Ctrl+S)**.
  4. Quay sang **Máy ảo VMware**, mở trình duyệt truy cập `http://192.168.101.1:3000`.
  5. Tại bảng **Danh sách văn bản công khai**, bấm nút **Xem** tại văn bản `VB-2026-0002` (hoặc nhập mã `VB-2026-0002` vào thanh tra cứu).
* **Kết quả quan sát**:
  - Hệ thống tính toán Auth Tag của thuật toán `AES-256-GCM` và đối chiếu mã băm `SHA-256` bằng hàm hằng thời gian `crypto.timingSafeEqual()`.
  - Phát hiện sai lệch ngay lập tức, trả về mã lỗi: **`HTTP 422 Unprocessable Entity`** (`STORAGE_TAMPERED`).
  - Giao diện người dùng chuyển sang khung thông báo **CẢNH BÁO MÀU ĐỎ**:
    > **"Cảnh báo an toàn: Bản mã văn bản lưu trữ trên máy chủ đã bị can thiệp trái phép! Hệ thống từ chối giải mã và từ chối tải xuống để bảo vệ người dùng."**
  - Nút tải tệp gốc bị vô hiệu hóa hoàn toàn.
* **Kiểm chứng trên máy thật**:
  Chạy công cụ kiểm tra độ lệch mã băm:
  ```powershell
  npm run tool:sha
  ```
  -> Dòng văn bản tương ứng hiển thị trạng thái lệch mã băm gốc (**Hash Baseline Drift Detected**).

---

### Kịch Bản 5: Tải lên tệp thực thi độc hại giả mạo (`.exe`, XSS)

* **Bối cảnh tấn công**: Kẻ tấn công cố tình tải lên tệp thực thi nguy hiểm hoặc chèn mã kịch bản XSS giả danh văn bản hành chính để lừa người dùng tải về thực thi.
* **Thao tác thực hiện trên máy ảo**:
  1. Đăng nhập thành công tài khoản cán bộ phát hành (`issuer_admin` / `Admin@123` / OTP từ ứng dụng hoặc `JBSWY3DPEHPK3PXP`).
  2. Tại khung **Tải lên văn bản mới**, thực hiện một trong hai hành vi:
     - Chọn một tệp có phần mở rộng bị cấm: `.exe`, `.bat`, `.cmd`, `.ps1`, `.sh`, `.vbs`, `.js`.
     - Hoặc nhập tiêu đề văn bản có chứa mã kịch bản: `<script>alert('Hacked')</script>`.
  3. Nhập mã xác nhận lưu trữ `UIT-SIGN-2026` và bấm nút **Lưu trữ văn bản**.
* **Kết quả quan sát**:
  - Bộ lọc kiểm soát đầu vào tại máy chủ phát hiện ngay tệp nguy hiểm.
  - Phản hồi mã lỗi: **`HTTP 400 Bad Request`** (`MALICIOUS_OR_FORGED_INPUT`).
  - Hệ thống từ chối xử lý, không ký số, không mã hóa và không lưu tệp vào kho đĩa.

---

### Kịch Bản 6: Mở liên kết chia sẻ đã hết hạn (Expired Share Link Replay)

* **Bối cảnh tấn công**: Kẻ tấn công thu thập được một liên kết chia sẻ văn bản cũ trong quá khứ và cố tình truy cập lại sau khi liên kết đã hết hiệu lực.
* **Thao tác thực hiện trên máy ảo**:
  1. Mở trình duyệt Web trên máy ảo, gõ địa chỉ kèm mã chia sẻ không tồn tại hoặc đã quá hạn:
     ```text
     http://192.168.101.1:3000/?share=token_sai_hoac_token_da_het_han_thoi_gian
     ```
  2. Bấm nút **Tra cứu văn bản**.
* **Kết quả quan sát**:
  - Máy chủ kiểm tra trường `expires_at` trong bảng `share_links` so với thời gian thực `new Date().toISOString()`.
  - Phản hồi mã lỗi: **`HTTP 403 Forbidden`** (`LINK_EXPIRED`).
  - Giao diện từ chối hiển thị nội dung và từ chối cấp quyền tải tệp về máy.

---

## 6. Hướng Dẫn Trình Bày Trước Giảng Viên & Hội Đồng

Khi trình diễn đồ án, Đại ca nên thực hiện quy trình 4 bước sau để tạo ấn tượng mạnh nhất:

1. **Bước 1 — Trình diễn Luồng Nghiệp vụ Hợp lệ (Happy Path):**
   - Đăng nhập `issuer_admin` -> Tải lên 1 tệp Word `.docx` -> Ký số & Mã hóa thành công -> Tạo liên kết chia sẻ.
   - Mở cửa sổ ẩn danh đóng vai trò Người nhận tra cứu -> Hệ thống hiển thị **Tích Xanh (Hợp lệ)** và xem trước văn bản trực tuyến mượt mà.
2. **Bước 2 — Trình diễn Tấn công Mạng từ Máy ảo VMware (Network & API Defense):**
   - Mở máy ảo Win10, dùng Postman/cURL gọi trực tiếp `/api/documents` -> Nhận `404 Blackhole`.
   - Chạy lệnh quét lặp 10 lần -> Nhận `429 ANTI_FUZZING_BLOCKED` (Chứng minh khóa IP thành công).
3. **Bước 3 — Trình diễn Tấn công Can thiệp Dữ liệu (Tampering 1-byte):**
   - Mở HxD Hex Editor sửa 1 byte tệp `.enc` trên máy thật -> Trên máy ảo bấm mở văn bản -> Giao diện hiện **Cảnh báo Đỏ Rực (Từ chối giải mã)**.
4. **Bước 4 — Mở Công cụ Giám sát SOC & Đối chiếu SHA-256 trên Máy thật:**
   - Chạy `npm run tool:sha` -> Chứng minh phát hiện trôi lệch mã băm (Hash Drift).
   - Chạy `npm run tool:soc` -> Chứng minh nhật ký ghi nhận chính xác nguồn tấn công từ IP của máy ảo.
