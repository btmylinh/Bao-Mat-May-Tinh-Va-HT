---
name: attack-simulation
description: Kịch bản và kỹ thuật mô phỏng tấn công can thiệp dữ liệu (Tampering), mạo danh chữ ký (Signature Forgery) và brute-force để kiểm thử tính an toàn của hệ thống.
---

# Kỹ Thuật Mô Phỏng Tấn Công (Attack Simulation Skill)

## 1. Tấn công can thiệp dữ liệu (Byte Flipping / File Tampering)
- **Mục tiêu:** Chứng minh hệ thống không bao giờ tin tưởng dữ liệu đầu vào khi chưa xác minh.
- **Phương pháp:** Can thiệp đổi ngẫu nhiên 1 byte bất kỳ trong nội dung file nhị phân.
```javascript
export function tamperBuffer(buffer) {
  const tampered = Buffer.from(buffer);
  // Đảo ngược 1 bit của byte đầu tiên hoặc byte giữa file
  tampered[0] = tampered[0] ^ 0xFF;
  return tampered;
}
```
- **Kỳ vọng:** Khi đưa file đã bị sửa vào hàm xác minh `verifySignature` hoặc giải mã `decryptBuffer`, hệ thống ném ngoại lệ hoặc trả về `false`, giao diện chuyển sang trạng thái cảnh báo màu đỏ.

## 2. Tấn công mạo danh chữ ký (Forged Digital Signature)
- **Mục tiêu:** Chứng minh chỉ chữ ký tạo bởi Private Key hợp lệ của đơn vị phát hành mới được công nhận.
- **Phương pháp:** Kẻ tấn công tự sinh một cặp khóa RSA riêng (`attackerKeys`) rồi dùng khóa bí mật của mình để ký đè lên tài liệu của đơn vị phát hành.
- **Kỳ vọng:** Cổng xác thực đối chiếu với Public Key đã đăng ký của đơn vị phát hành, phát hiện chữ ký không khớp và từ chối tài liệu.
