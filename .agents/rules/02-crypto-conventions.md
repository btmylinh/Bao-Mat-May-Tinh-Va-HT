---
trigger: always_on
name: crypto-conventions
description: Quy chuẩn mật mã học cho Node.js crypto module (SHA-256, RSA/Ed25519, AES-256-GCM, PBKDF2/Bcrypt)
apply_to: ["src/**/*", "server.js", "app.js"]
tags: ["crypto", "security", "aes-256-gcm", "sha-256", "rsa", "digital-signature"]
---

# 02. Quy Chuẩn Mật Mã Học & Kiểm Chứng Dữ Liệu (Cryptography Standards)

Quy định bắt buộc về các thuật toán mã hóa, ký số và quản lý khóa mật mã trong dự án.

---

## 1. Mục Tiêu (Kết Quả Cuối Cùng)
* Đảm bảo tính bí mật (Confidentiality) qua mã hóa đối xứng AES-256-GCM.
* Đảm bảo tính toàn vẹn (Integrity) qua mã băm SHA-256.
* Đảm bảo tính xác thực và chống chối bỏ (Authenticity & Non-repudiation) qua Chữ ký số RSA-2048 hoặc Ed25519.
* Đảm bảo xác thực đa yếu tố (2FA) theo chuẩn RFC 6238 (TOTP).

---

## 2. Ranh Giới (Những Điều Tuyệt Đối KHÔNG ĐƯỢC LÀM)
* **Tuyệt đối KHÔNG dùng thuật toán lỗi thời hoặc mất an toàn**: Cấm dùng MD5, SHA-1, DES, 3DES, hoặc chế độ AES-ECB.
* **Tuyệt đối KHÔNG tái sử dụng IV (Initialization Vector)**: Mỗi lần mã hóa file bằng AES-256-GCM bắt buộc sinh ngẫu nhiên IV 12 bytes (`crypto.randomBytes(12)`).
* **Tuyệt đối KHÔNG bỏ qua Auth Tag**: Với AES-256-GCM, phải kiểm tra và xác thực Auth Tag (16 bytes); nếu sai tag, lập tức ngắt giải mã và ném lỗi can thiệp dữ liệu.
* **Tuyệt đối KHÔNG so sánh chuỗi hash hoặc chữ ký bằng toán tử `===`**: Luôn sử dụng `crypto.timingSafeEqual()` để chống tấn công phân tích thời gian thực thi (Timing Attack).

---

## 3. Tiêu Chuẩn Nghiệm Thu Mật Mã
* **Ký số:** Chữ ký tạo bởi Private Key của Issuer phải được xác minh thành công (`crypto.verify`) bằng Public Key tương ứng.
* **Chống giả mạo:** Bất kỳ sự thay đổi dù chỉ 1 bit của nội dung file hoặc bản chữ ký đều làm hàm `verify` trả về `false`.
* **Mã hóa lưu trữ:** File trong thư mục `storage/` khi mở trực tiếp bằng text editor phải ở dạng nhị phân mã hóa hoàn toàn, không lộ chuỗi ký tự gốc.
