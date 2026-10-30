---
trigger: always_on
name: project-overview
description: Tổng quan hệ thống Zero-Trust Document Vault, kiến trúc bảo mật Node.js, luồng dữ liệu và quy ước dự án
apply_to: ["**/*"]
tags: ["overview", "project", "security", "zero-trust", "crypto", "architecture"]
---

# 01. Tổng Quan Hệ Thống & Kiến Trúc Kỹ Thuật (Project Overview)

Tài liệu định hình kiến trúc toàn cục, ngăn xếp công nghệ và nguyên lý an toàn thông tin cốt lõi của đồ án **Zero-Trust Document Vault**.

---

## 1. Mục Tiêu (Kết Quả Cuối Cùng)
* Xây dựng hệ thống lưu trữ và kiểm chứng văn bản mật chống giả mạo, đáp ứng trọn vẹn yêu cầu đồ án môn Bảo mật mạng máy tính và hệ thống.
* Hiện thực hóa thông điệp cốt lõi: *"Không phải mọi thông tin nhận được đều đáng tin cậy"* -> Mọi văn bản, yêu cầu tải và chữ ký đều phải qua cơ chế kiểm chứng mã hóa trước khi chấp nhận.
* Tích hợp trọn gói Backend Express và Frontend SPA trong 1 tiến trình Node.js duy nhất (`npm start`), đảm bảo demo nhanh, trực quan và không xung đột môi trường.

---

## 2. Ranh Giới (Những Điều Tuyệt Đối KHÔNG ĐƯỢC LÀM)
* **Tuyệt đối KHÔNG tin tưởng dữ liệu đầu vào**: Không bao giờ trả file về cho người dùng nếu chữ ký số hoặc mã băm SHA-256 bị sai lệch.
* **Tuyệt đối KHÔNG lưu trữ file thô (plaintext) trên ổ đĩa**: Toàn bộ nội dung tài liệu lưu trong `storage/` bắt buộc phải được mã hóa bằng AES-256-GCM.
* **Tuyệt đối KHÔNG lưu Private Key ở Frontend**: Khóa bí mật chỉ nằm tại tầng Backend hoặc cấu hình an toàn, máy khách chỉ nhận Public Key để xác minh.
* **Tuyệt đối KHÔNG hardcode mật khẩu hay secret key trong mã nguồn**: Sử dụng cấu hình tập trung hoặc file môi trường mẫu `.env.example`.

---

## 3. Tiêu Chuẩn Nghiệm Thu Kỹ Thuật
* **Backend:** Khởi chạy ổn định tại cổng mạng định trước (mặc định port `3000`), không để rò rỉ tiến trình nền.
* **Cơ sở dữ liệu:** SQLite cục bộ ghi nhận đầy đủ siêu dữ liệu (metadata), khóa công khai (public keys) và nhật ký kiểm tra (audit logs).
* **Giao diện:** Đảm bảo hiển thị tức thì trạng thái Xanh (Hợp lệ) và Đỏ (Cảnh báo giả mạo / can thiệp byte) khi thao tác kiểm chứng.
