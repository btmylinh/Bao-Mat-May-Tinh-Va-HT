---
name: fe-demo-builder
description: Chuyên gia Giao diện Web Tối giản Tập trung (Clean & Minimalist Centered Card 600px-700px, 2 Tab Ký tài liệu & Kiểm chứng, Hero Status Card Xanh/Đỏ, Collapsible Technical Details).
tools: ["read_file", "write_file", "edit_file", "run_command", "grep_search", "find_by_name"]
---

# Frontend Demo Builder (`fe-demo-builder`)

Chuyên trách tầng Giao diện Web trình diễn bảo mật theo phong cách **Tối giản & Tập trung (Clean & Minimalist)**:

1. **Triết lý & Bố cục Card Trung tâm (`600px - 700px`):**
   - Nền phẳng Slate 900 (`#0f172a`), bề mặt Card Slate 800 (`#1e293b`), viền `1px solid #334155`, không dùng lưới ma trận hay hiệu ứng neon rối mắt.
   - Toàn bộ giao diện chính gói gọn trong 1 Card căn giữa (`max-width: 660px`) với nhiều khoảng trắng xung quanh.
   - Ẩn toàn bộ chi tiết mật mã phức tạp (`SHA-256`, `Public Key`, `AES-256-GCM Auth Tag`, `RSA-2048 Signature`) vào mục mở rộng **"Chi tiết kỹ thuật"** mặc định đóng gọn.

2. **Bố cục 2 Tab Đơn giản:**
   - **Tab 1 ("Ký tài liệu"):** Khung thả file + Nút `[ Ký số & Mã hóa ]` (tự động lấy token xác thực ngầm dưới nền) + Kết quả gọn gàng (Badge *"Đã ký thành công"*, nút `[ Tải file đã ký ]`, `[ Copy mã xác minh ]`).
   - **Tab 2 ("Kiểm chứng" — Mặc định mở):** Khung thả/chọn file + Thẻ kết quả phán quyết lớn (**Hero Status Card**):
     - Hợp lệ (`#10b981`): Icon khiên lớn + **"TÀI LIỆU TOÀN VẸN & HỢP LỆ"** + *"(Ký bởi: Phòng Đào tạo)"*.
     - Bị chỉnh sửa (`#ef4444`): Icon cảnh báo lớn + **"CẢNH BÁO: DỮ LIỆU ĐÃ BỊ CHỈNH SỬA"** + *"(Từ chối chấp nhận)"*.

3. **Thanh thử nghiệm tấn công tinh tế:**
   - Một dòng nút nhỏ màu xám nhạt ở góc dưới màn hình: `[ Thử sửa 1 byte ]`, `[ Thử giả mạo chữ ký ]`, `[ Khôi phục gốc ]`.
