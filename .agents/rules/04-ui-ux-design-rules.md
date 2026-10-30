---
trigger: always_on
name: ui-ux-design-rules
description: Quy chuẩn thiết kế giao diện phần mềm thuần túy (Clean Light Mode, 4 chức năng Tải lên, Ký số, Mã hóa, Chia sẻ & Tải về; không đặt bảng soi SHA-256 hay nút giả lập lên Web UI)
apply_to: ["public/**/*", "src/views/**/*", "views/**/*"]
tags: ["ui", "ux", "frontend", "clean-light-mode", "pure-software"]
---

# 04. Quy Chuẩn Thiết Kế Giao Diện Phần Mềm Thuần Túy (UI/UX Rules)

Quy định chuẩn mực thiết kế giao diện Web như một **phần mềm quản lý và chia sẻ văn bản bảo mật thực thụ**: Giao diện Web chỉ phục vụ 4 chức năng nghiệp vụ chính (**Tải lên -> Ký số -> Mã hóa -> Chia sẻ & Tải về**), còn việc theo dõi mã băm `SHA-256` và giả lập tấn công được thực hiện hoàn toàn bằng công cụ dòng lệnh bên ngoài.

---

## 1. Bản Chất Giao Diện (Phần Mềm Thuần 100%)
* **Tuyệt đối KHÔNG biến giao diện Web thành công cụ soi mã băm hay mô phỏng:**
  - **KHÔNG** hiển thị bất kỳ bảng so sánh mã băm `SHA-256`, `IV 12B`, `Auth Tag 16B` hay mục "Chi tiết kỹ thuật" nào trên giao diện Web.
  - **KHÔNG** đặt thanh công cụ giả lập tấn công trên giao diện Web.
* **4 chức năng nghiệp vụ cốt lõi trên Web:**
  1. **Tải lên văn bản** (chọn tệp từ máy tính hoặc nhập nội dung + người ký).
  2. **Ký số (`RSA-PSS`)** tự động khi lưu văn bản.
  3. **Mã hóa (`AES-256-GCM`)** lưu trữ an toàn vào kho.
  4. **Chia sẻ & Tải về** (tạo liên kết chia sẻ có thời hạn, mở liên kết chia sẻ hoặc tải văn bản từ kho sau khi hệ thống xác thực chữ ký & giải mã ngầm).

---

## 2. Cấu Trúc 2 Tab Phần Mềm (`Clean Light Mode`)
1. **Tab 1 — `1. Tải lên, Ký số & Mã hóa`:**
   - Khung kéo thả / chọn tệp văn bản, ô nhập `Tên tệp văn bản`, `Người ký / Đơn vị` và `Nội dung văn bản`.
   - Nút hành động chính: **`Tải lên, Ký số & Mã hóa`**.
   - Khối xác nhận lưu trữ an toàn đi kèm chức năng **`Chia sẻ văn bản cho người nhận`** (chọn thời hạn 15 phút / 1 giờ / 24 giờ, nút `Tạo liên kết chia sẻ`, ô hiển thị liên kết và nút `Sao chép`).
2. **Tab 2 — `2. Kho Văn bản & Chia sẻ`:**
   - Khu vực **`Mở văn bản được chia sẻ`**: Ô nhập liên kết/mã chia sẻ kèm nút **`Xác thực & Tải văn bản`**.
   - Khung thông báo trạng thái xác thực & giải mã:
     - Hợp lệ (Xanh `#ecfdf5` / `#10b981`): **`Đã xác thực chữ ký số hợp lệ & giải mã văn bản thành công`**, hiển thị nội dung đã giải mã và nút **`Tải tệp gốc về máy`**.
     - Bị can thiệp / Giả mạo chữ ký (Đỏ `#fef2f2` / `#ef4444`): **`Cảnh báo bảo mật: Văn bản đã bị can thiệp trái phép hoặc chữ ký số không hợp lệ! Hệ thống từ chối giải mã và chia sẻ.`**
   - Danh sách **`Kho văn bản đã ký số & mã hóa`**: Hiển thị tên tệp, người ký, dung lượng, thời gian và 2 nút **`Chia sẻ`** & **`Tải về`**.
