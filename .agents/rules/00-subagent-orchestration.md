---
trigger: always_on
name: dack-subagent-orchestration
description: Quy định bắt buộc Worker DACK điều phối 4 Subagent chuyên biệt (research, crypto-sec-builder, fe-demo-builder, qa-attack-tester) chạy song song để tối ưu tốc độ và ngữ cảnh
apply_to: ["**/*"]
tags: ["subagent", "orchestration", "parallel", "research", "crypto-sec-builder", "fe-demo-builder", "qa-attack-tester"]
---

# 00. Quy Chuẩn Điều Phối 4 Subagent Nội Bộ Của Worker DACK

Để giữ ngữ cảnh phiên chính luôn nhẹ và suy luận nhanh, Worker chính đóng vai trò **Nhạc trưởng (Coordinator)** và điều phối 4 Subagent chuyên biệt qua công cụ `invoke_subagent`:

| Subagent (`TypeName`) | Vai trò chuyên trách |
| :--- | :--- |
| **`research`** *(Built-in)* | Khảo sát đề án, tài liệu yêu cầu và mã nguồn hiện có, trả về bảng tóm tắt ngắn gọn. |
| **`crypto-sec-builder`** | Thực thi tầng Mật mã học (`node:crypto`: SHA-256, RSA/Ed25519 Signature, AES-256-GCM, `timingSafeEqual`), API Express, 2FA TOTP và cơ sở dữ liệu SQLite. |
| **`fe-demo-builder`** | Thực thi giao diện Web trình diễn bảo mật (Dark Mode Glassmorphism, Issuer Panel, Public Verification Portal, Attack Simulation Bar). |
| **`qa-attack-tester`** | Kiểm soát cổng mạng (`netstat`), chạy kịch bản kiểm thử tấn công tự động (Happy Path, Tampering 1-byte, Signature Forgery, Expired Token, 2FA) và chụp ảnh nghiệm thu trực quan. |

## Luồng Điều Phối 3 Nhịp
1. **Nhịp 1 (`research`)**: Khảo sát & chốt API Contract giữa Backend Crypto và Frontend Demo.
2. **Nhịp 2 (`crypto-sec-builder` // `fe-demo-builder` song song)**: Triển khai song song tầng Backend/Crypto và tầng Giao diện Web trình diễn.
3. **Nhịp 3 (`qa-attack-tester`)**: Chạy kịch bản kiểm thử tấn công (Đỏ -> Xanh), chụp ảnh màn hình và dùng `read_file` kiểm tra trực tiếp trước khi báo cáo.
