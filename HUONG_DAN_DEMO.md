# Hướng Dẫn Thao Tác Trình Diễn — Cổng Văn bản & Hồ sơ Điện tử

Tài liệu hướng dẫn trình diễn hệ thống theo mô hình **2 Tác nhân (Actors)** và **7 Use Case thuần nghiệp vụ (`UC01 -> UC07`)**, phân loại văn bản **Công khai (`PUBLIC`) / Nội bộ (`PRIVATE`)**, kiểm chứng **Đường hầm Mã hóa Hai chiều (`POST /api/zt-tunnel` + `ztEncryptedResponse`)** trên công cụ DevTools (F12 Network) và kết hợp bộ công cụ dòng lệnh (CLI) bên ngoài để đối chiếu `hash_baseline.txt`, kiểm tra `Key Inventory`, phân tích log `SOC SHIFT` cùng bộ kiểm thử tự động `27/27` ca.

---

## 1. Khởi động Hệ thống

Mở Terminal tại thư mục gốc của đồ án và chạy:

```bash
npm start
```

Mở trình duyệt truy cập: **`http://localhost:3000`**

Khi khởi chạy lần đầu, hệ thống tự động khởi tạo sẵn 2 văn bản mẫu để phục vụ trình diễn ngay:
- **`VB-2026-0001`** (`Quyet_Dinh_Cong_Nhan_Tot_Nghiep_2026.txt`) — Phạm vi: **Công khai (`PUBLIC`)** (xuất hiện trực tiếp trên bảng Danh sách văn bản công khai ở trang chủ).
- **`VB-2026-0002`** (`Hop_Dong_Ngan_Sach_Noi_Bo_2026.txt`) — Phạm vi: **Nội bộ (`PRIVATE`)** (ẩn khỏi bảng công khai, chỉ mở được khi nhập đúng mã `VB-2026-0002` hoặc liên kết chia sẻ).

---

## 2. Trình diễn 7 Use Case thuần nghiệp vụ trên Giao diện Web

### Nhóm 2 — Cổng Tra cứu & Tiếp nhận Văn bản (Tác nhân: Người nhận / Khách — Không cần đăng nhập)
1. **Xem danh sách văn bản công khai & Lọc nhanh**:
   - Tại màn hình trang chủ mặc định, bảng **Danh sách văn bản công khai** ở phía dưới chỉ hiển thị các văn bản có phạm vi `Công khai` (`VB-2026-0001`). Các văn bản `Nội bộ` (`VB-2026-0002`) hoàn toàn được ẩn đi.
2. **UC05 (Mở và Tra cứu văn bản theo mã / liên kết)**:
   - Bấm nút **`Xem`** tại dòng văn bản công khai `VB-2026-0001`, hoặc nhập trực tiếp mã văn bản nội bộ **`VB-2026-0002`** (hay dán liên kết chia sẻ `?share=...`) vào thanh tra cứu và bấm **`Tra cứu văn bản`**.
3. **UC06 (Xem trước nội dung văn bản trực tuyến)**:
   - Hệ thống hiển thị khung thông tin văn bản gồm: Mã định danh, Tên tệp, Cơ quan ban hành, Ngày ban hành, Kích thước và khung đọc nội dung văn bản trực tuyến (hỗ trợ cả văn bản thuần `.txt` và trích xuất định dạng bảng/đoạn văn từ tệp Word `.docx`).
4. **UC07 (Tải tệp văn bản về máy tính)**:
   - Bấm nút **`Tải tệp về máy`** ở góc phải khung xem trước để tải tệp gốc về máy tính.

### Nhóm 1 — Cổng Quản trị & Phát hành Văn bản (Tác nhân: Người phát hành / Đơn vị ban hành)
5. **UC01 (Đăng nhập hệ thống)**:
   - Bấm nút **`Đăng nhập Cán bộ phát hành`** ở góc phải Header -> Nhập tài khoản `issuer_admin` và mật khẩu `Admin@123` -> Bấm **`Đăng nhập`**.
6. **UC03 (Quản lý danh mục kho văn bản)**:
   - Sau khi đăng nhập, bảng **Danh mục Kho văn bản đã ban hành** hiển thị đầy đủ cả văn bản `Công khai` lẫn `Nội bộ`, gồm các cột: `Mã định danh`, `Tên tệp`, `Cơ quan ban hành`, `Ngày ban hành`, `Kích thước`, `Phạm vi` (`Công khai` / `Nội bộ`), `Trạng thái phát hành` (`Đã ban hành` / `Đang chia sẻ`) kèm các thao tác `Chia sẻ`, `Xem`, `Xóa`.
7. **UC02 (Tải lên và Lưu trữ văn bản mới)**:
   - Bấm **`+ Tải lên văn bản mới`** -> Chọn tệp (`.txt`, `.docx`, `.pdf`...) hoặc nhập nội dung, điền Tên văn bản, Cơ quan ban hành, chọn **Phạm vi văn bản** (`Công khai` hoặc `Nội bộ`), nhập Mã xác nhận lưu trữ (`UIT-SIGN-2026`) -> Bấm **`Lưu trữ văn bản`**.
8. **UC04 (Tạo liên kết chia sẻ văn bản)**:
   - Bấm nút **`Chia sẻ`** trên dòng văn bản -> Chọn thời hạn hiệu lực của liên kết (`7 ngày`, `30 ngày`, `90 ngày`, `1 năm`) -> Bấm **`Tạo liên kết chia sẻ`** và **`Sao chép liên kết`** để gửi cho người nhận.

---

## 3. Kiểm chứng Tăng cường Bảo mật 4 Lớp & Đường hầm Mã hóa Hai chiều

Hệ thống vận hành cơ chế **Zero-Trust 4-Layer Security Hardening**:
1. **Lớp 1 — Mã hóa chuỗi Endpoint (`String Obfuscation`)**: Toàn bộ đường dẫn trong `public/app.js` được giải mã động lúc chạy (`XOR 0x5A + Hex`), hoàn toàn không chứa chuỗi `/api/` dạng rõ trong mã nguồn giao diện (`0 match`).
2. **Lớp 2 — Bắt buộc Đường hầm (`Strict Tunnel Mode - 404 Blackhole`)**: Mọi yêu cầu (`GET`, `POST`, `DELETE` và cả tải tệp `FormData`) đều đi qua duy nhất `POST /api/zt-tunnel` với `ztEncryptedPayload` và nhận về `ztEncryptedResponse` (`AES-256-GCM`). Mọi truy vấn gọi thẳng vào đường dẫn nghiệp vụ bên ngoài đường hầm đều nhận `HTTP 404 Not Found` (Blackhole).
3. **Lớp 3 — Lá chắn Chống DevTools & Anti-Hooking (`initSecurityShield`)**: Tự động chặn phím tắt `F12`, `Ctrl+Shift+I/J/C`, `Ctrl+U`, chặn chuột phải `contextmenu` và đóng băng (`Object.freeze`) các hàm mật mã/JSON.
4. **Lớp 4 — Chống Quét Từ điển (`Anti-Fuzzing Guard - HTTP 429`)**: Tự động khóa tạm thời IP bằng mã lỗi `HTTP 429 ANTI_FUZZING_BLOCKED` nếu gửi liên tiếp từ 10 yêu cầu quét đường dẫn hoặc gói tin sai định dạng trong 1 phút.

---

## 4. Công cụ Dòng lệnh (CLI) Đối chiếu SHA-256 Baseline, SOC Log & Kiểm thử Tự động

Mở cửa sổ Terminal thứ hai để chạy các công cụ kiểm tra và giám sát độc lập:

- **Đối chiếu `SHA-256`, `hash_baseline.txt`, Phong bì lai `DEK/KEK` & `key_inventory.csv`**:
  ```bash
  npm run tool:sha
  ```
- **Phân tích nhật ký xác thực `data/auth_events.csv` (Phát hiện Brute-force & Password Spraying theo `MITRE ATT&CK T1110`)**:
  ```bash
  npm run tool:soc
  ```
- **Chạy trọn bộ 28 ca kiểm thử bảo mật tự động (`Unit Crypto` + `TC01 -> TC27`, bao gồm Đường hầm Mã hóa Hai chiều `/api/zt-tunnel` & 4 Lớp Gia cố Bảo mật)**:
  ```bash
  npm test
  ```
