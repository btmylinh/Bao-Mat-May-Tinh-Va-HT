---
trigger: always_on
name: security-and-testing
description: Quy chuẩn kiểm thử bảo mật, kịch bản tấn công mô phỏng, quản lý session JWT, 2FA và ma trận kiểm thử
apply_to: ["tests/**/*", "test/**/*", "src/**/*"]
tags: ["testing", "security", "tampering", "testcases", "2fa", "audit"]
---

# 03. Tiêu Chuẩn Kiểm Thử & Mô Phỏng Tấn Công (Security & Testing Standards)

Quy định thực thi bộ test case và kịch bản mô phỏng tấn công phục vụ thuyết trình và nghiệm thu đồ án.

---

## 1. Mục Tiêu (Kết Quả Cuối Cùng)
* Cung cấp trọn vẹn 6 ca kiểm thử theo đúng bảng nghiệm thu tại file đề án: từ ca hợp lệ (Happy Path) đến các ca rủi ro / tấn công (Attack Scenarios).
* Xây dựng bộ script kiểm thử tự động có khả năng chạy độc lập để chứng minh trước hội đồng chấm thi: kiểm thử phải có lúc ĐỎ (thất bại khi bị tấn công) và XANH (thành công khi dữ liệu hợp lệ).

---

## 2. Ranh Giới (Những Điều Tuyệt Đối KHÔNG ĐƯỢC LÀM)
* **Tuyệt đối KHÔNG hardcode kết quả "Success" ảo**: Mọi phản hồi kiểm chứng phải thông qua tính toán mật mã thật bằng CPU (`crypto.createHash`, `crypto.verify`).
* **Tuyệt đối KHÔNG bỏ qua trường hợp file bị sửa**: Test case phát hiện can thiệp (Tampering) bắt buộc phải sửa byte thực tế trên file mẫu và ghi nhận lỗi `INTEGRITY_VIOLATION`.
* **Tuyệt đối KHÔNG duy trì tiến trình nền sau khi chạy test**: Mọi kết nối SQLite và máy chủ test phải được dọn dẹp trong khối `finally` hoặc sau khi hoàn tất test suite.

---

## 3. Ma Trận Nghiệm Thu (Acceptance Matrix)
1. **TC01 - Sign & Encrypt:** Tải file, mã hóa AES-256 lưu kho, ký số RSA/ECDSA -> Trạng thái: PASS.
2. **TC02 - Verify Integrity:** Kiểm tra file nguyên bản -> Trạng thái: PASS (Tick Xanh).
3. **TC03 - Tamper Detection:** Sửa 1 byte file -> Trạng thái: REJECT (Cảnh báo Đỏ).
4. **TC04 - Forged Signature:** Ký đè bằng Private Key khác -> Trạng thái: REJECT (Cảnh báo Đỏ).
5. **TC05 - Expired Access:** Dùng link chia sẻ quá hạn -> Trạng thái: 403 Forbidden.
6. **TC06 - 2FA Enforcement:** Nhập sai mã TOTP -> Trạng thái: 401 Unauthorized.
