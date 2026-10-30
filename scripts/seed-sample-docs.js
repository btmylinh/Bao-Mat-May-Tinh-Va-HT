import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  getDatabase,
  getUserByUsername,
  insertDocument,
  createShareLink,
  logAuditEvent,
  syncHashBaselineFile,
  DEFAULT_ACTIVE_KEY_ID,
} from '../src/db/database.js';
import {
  calculateHash,
  signData,
  buildEnvelopeAad,
  encryptEnvelopeBuffer,
} from '../src/crypto/cryptoService.js';
import { createSampleDocxBuffer } from '../src/utils/docExtractor.js';

const WORD_MIME_TYPE =
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

function seedSampleDocuments() {
  const db = getDatabase();
  const issuer = getUserByUsername('issuer_admin');
  if (!issuer) {
    console.error('Không tìm thấy tài khoản issuer_admin trong hệ thống!');
    process.exit(1);
  }

  const storageDir = path.resolve(process.cwd(), 'storage');
  fs.mkdirSync(storageDir, { recursive: true });

  // 1. Tạo buffer cho file Quyết định tốt nghiệp (.docx)
  const quyetDinhDocxBuffer = createSampleDocxBuffer(
    [
      'TRƯỜNG ĐẠI HỌC CÔNG NGHỆ THÔNG TIN',
      'HỘI ĐỒNG XÉT TỐT NGHIỆP ĐẠI HỌC',
      'Số: 256/QĐ-ĐHCNTT-2026                    TP. Hồ Chí Minh, ngày 28 tháng 10 năm 2026',
      '',
      'QUYẾT ĐỊNH',
      'Về việc công nhận tốt nghiệp và trao chứng nhận Đồ án Xuất sắc ngành An toàn Thông tin',
      '',
      'HIỆU TRƯỞNG TRƯỜNG ĐẠI HỌC CÔNG NGHỆ THÔNG TIN',
      '- Căn cứ Quy chế đào tạo đại học chính quy trình độ kỹ sư/cử nhân hiện hành;',
      '- Căn cứ kết quả bảo vệ đồ án môn học Bảo mật Mạng máy tính và Hệ thống năm học 2026;',
      '- Theo đề nghị của Trưởng khoa Mạng máy tính & Truyền thông và Hội đồng thẩm định đồ án;',
      '',
      'QUYẾT ĐỊNH:',
      'Điều 1. Công nhận kết quả bảo vệ đồ án đạt loại Xuất sắc cho sinh viên Bùi Thị Mỹ Linh (MSSV: 1150080145) với công trình nghiên cứu: "Zero-Trust Document Vault: Nền tảng Lưu trữ và Chia sẻ Văn bản Chống Giả mạo đa tầng".',
      'Điều 2. Danh sách khen thưởng và phân loại đồ án chi tiết được ghi nhận tại bảng dưới đây.',
      'Điều 3. Văn bản này được ký số điện tử bằng khóa RSA-2048 và lưu trữ dưới dạng mã hóa phong bì lai AES-256-GCM. Bản nhị phân nguyên vẹn có giá trị pháp lý và được kiểm chứng tức thì qua mã băm SHA-256.',
    ],
    {
      tableHeaders: ['STT', 'Họ và tên sinh viên', 'Mã số sinh viên', 'Tên đề tài đồ án', 'Xếp loại đánh giá'],
      tableRows: [
        ['01', 'Bùi Thị Mỹ Linh', '1150080145', 'Zero-Trust Document Vault Security System', 'Xuất sắc (9.8/10)'],
        ['02', 'Lê Minh Quân', '22520888', 'Network Perimeter Defense & TLS Hardening', 'Xuất sắc (9.5/10)'],
        ['03', 'Phạm Ngọc Bảo Trân', '22520912', 'Public Key Infrastructure & Key Lifecycle', 'Giỏi (9.0/10)'],
      ],
    }
  );

  // 2. Tạo buffer cho file Hợp đồng nghiên cứu bảo mật (.docx)
  const hopDongDocxBuffer = createSampleDocxBuffer(
    [
      'BAN GIÁM ĐỐC TRUNG TÂM AN NINH MẠNG',
      'HỆ THỐNG PHÒNG THỦ KHÔNG TIN CẬY (ZERO-TRUST)',
      'Số: 88/HĐ-NC-ATTT-2026                    Hà Nội, ngày 10 tháng 10 năm 2026',
      '',
      'HỢP ĐỒNG',
      'Nghiên cứu & Chuyển giao Công nghệ Bảo vệ Văn bản Mật Cấp cao',
      '',
      'CĂN CỨ VÀ NỘI DUNG THỎA THUẬN:',
      'Điều 1. Phạm vi bảo mật: Toàn bộ khóa bí mật RSA-2048, khóa dữ liệu AES-256-GCM và cấu trúc đường hầm mã hóa hai chiều Zero-Trust Tunnel được xếp loại TỐI MẬT.',
      'Điều 2. Phân loại tài liệu: NỘI BỘ (PRIVATE). Tài liệu này được ẩn hoàn toàn trên Cổng tra cứu công khai và chỉ có thể mở thông qua liên kết chia sẻ mã hóa có thời hạn truy cập.',
      'Điều 3. Tiến độ thực hiện và phân kỳ kinh phí giải ngân được quy định tại bảng dưới đây.',
    ],
    {
      tableHeaders: ['Giai đoạn', 'Hạng mục bảo mật triển khai', 'Mã thuật toán áp dụng', 'Thời hạn bàn giao', 'Kinh phí dự toán'],
      tableRows: [
        ['Giai đoạn 1', 'Mã hóa lai DEK & KEK + Gắn thẻ AAD', 'AES-256-GCM + RSA-OAEP', '30 ngày', '150.000.000 VNĐ'],
        ['Giai đoạn 2', 'Chống quét API & Đường hầm hai chiều', 'HMAC-SHA256 Anti-Replay', '20 ngày', '120.000.000 VNĐ'],
        ['Giai đoạn 3', 'Phát hiện rủi ro & Cảnh báo xâm nhập', 'SOC MITRE ATT&CK T1110', '15 ngày', '90.000.000 VNĐ'],
      ],
    }
  );

  // 3. Tạo buffer cho file Biên bản kiểm kê khóa HSM (.docx)
  const bienBanDocxBuffer = createSampleDocxBuffer(
    [
      'BỘ TẬP TRUNG KHÓA MẬT MÃ QUỐC GIA',
      'TỔ QUẢN TRỊ VÒNG ĐỜI KHÓA KEY INVENTORY',
      'Số: 14/BB-KK-2026                         TP. Hồ Chí Minh, ngày 25 tháng 10 năm 2026',
      '',
      'BIÊN BẢN',
      'Kiểm kê & Đánh giá An toàn Thiết bị Ký số Phần cứng (HSM) Quý 4/2026',
      '',
      'HỘI ĐỒNG KIỂM KÊ XÁC NHẬN:',
      '- Thời gian kiểm kê: 08:30 ngày 25 tháng 10 năm 2026.',
      '- Địa điểm: Phòng máy chủ trung tâm bảo mật thông tin.',
      '- Tình trạng niêm phong: Nguyên vẹn, không có dấu hiệu can thiệp vật lý hay trích xuất bộ nhớ tạm.',
      '- Danh mục các cặp khóa mật mã đã đối soát và cập nhật vào danh bạ an toàn được thể hiện tại bảng sau.',
    ],
    {
      tableHeaders: ['Key Identifier', 'Trạng thái', 'Thuật toán & Kích thước', 'Dấu vân tay SPKI SHA-256', 'Ghi chú kỹ thuật'],
      tableRows: [
        ['vault-rsa-prod-2026Q4', 'ACTIVE', 'RSA-OAEP-SHA256 (2048-bit)', '70bc2b1dc23ba511038f9e6bdf...', 'Khóa chính đang dùng ký & mã hóa'],
        ['vault-rsa-retired-2026Q3', 'RETIRED', 'RSA-OAEP-SHA256 (2048-bit)', '57b6afd548daa42bb33fd0d9f0...', 'Khóa cũ đã thu hồi, chỉ lưu trữ'],
        ['vault-rsa-qa-2026Q4', 'QA_ONLY', 'RSA-OAEP-SHA256 (2048-bit)', '42cc346346ac662ff0af6df1ed...', 'Khóa thử nghiệm kiểm thử tấn công'],
      ],
    }
  );

  // 4. Đọc tệp Word đồ án thực tế có sẵn trên đĩa nếu tồn tại
  let existingDoAnDocxBuffer = null;
  const doAnFilePath = path.resolve(
    process.cwd(),
    'Do_an_cuoi_ky_Bao_mat_mang_may_tinh_va_he_thong.docx'
  );
  if (fs.existsSync(doAnFilePath)) {
    existingDoAnDocxBuffer = fs.readFileSync(doAnFilePath);
    console.log(`+ Tìm thấy tệp Word thực tế: Do_an_cuoi_ky_Bao_mat_mang_may_tinh_va_he_thong.docx (${existingDoAnDocxBuffer.length} bytes)`);
  }

  const sampleDocs = [
    {
      title: 'Quyết định công nhận tốt nghiệp Đại học chính quy đợt 2 năm 2026',
      filename: 'Quyet_Dinh_Tot_Nghiep_2026.docx',
      mimeType: WORD_MIME_TYPE,
      visibility: 'PUBLIC',
      signerName: 'Hiệu Trưởng - Hội Đồng Tốt Nghiệp',
      buffer: quyetDinhDocxBuffer,
      createShare: true,
      shareExpiresHours: 72,
      recipientEmail: 'sinhvien.mylinh@uit.edu.vn',
    },
    {
      title: 'Hợp đồng nghiên cứu & phát triển hệ thống bảo vệ văn bản mật',
      filename: 'Hop_Dong_Nghien_Cuu_Bao_Mat_2026.docx',
      mimeType: WORD_MIME_TYPE,
      visibility: 'PRIVATE',
      signerName: 'Ban Giám Đốc Trung Tâm An Ninh Mạng',
      buffer: hopDongDocxBuffer,
      createShare: true,
      shareExpiresHours: 168, // 7 days
      recipientEmail: 'linh.tran@company.vn',
    },
    {
      title: 'Biên bản kiểm kê thiết bị & bàn giao cặp khóa mật mã RSA-2048',
      filename: 'Bien_Ban_Kiem_Ke_Mat_Ma_HSM_2026.docx',
      mimeType: WORD_MIME_TYPE,
      visibility: 'PRIVATE',
      signerName: 'Tổ Quản Trị Vòng Đời Khóa Mật Mã',
      buffer: bienBanDocxBuffer,
      createShare: true,
      shareExpiresHours: 72,
      recipientEmail: 'kiemtoan.antoan@company.vn',
    },
  ];

  if (existingDoAnDocxBuffer) {
    sampleDocs.unshift({
      title: 'Báo cáo thuyết minh Đồ án Cuối kỳ Bảo mật mạng máy tính và hệ thống',
      filename: 'Bao_Cao_Do_An_Cuoi_Ky_Bao_Mat_He_Thong.docx',
      mimeType: WORD_MIME_TYPE,
      visibility: 'PUBLIC',
      signerName: 'Hội Đồng Chấm Thi & Thẩm Định Đồ Án',
      buffer: existingDoAnDocxBuffer,
      createShare: true,
      shareExpiresHours: 8760, // 1 year
      recipientEmail: 'giangvien.chamthi@uit.edu.vn',
    });
  }

  console.log('Bắt đầu khởi tạo các tệp Word (.docx) mẫu vào kho bảo mật...');

  for (const doc of sampleDocs) {
    const existing = db
      .prepare('SELECT id FROM documents WHERE original_filename = ?')
      .get(doc.filename);
    if (existing) {
      console.log(`- Tài liệu [${doc.filename}] đã tồn tại (ID: ${existing.id}), bỏ qua.`);
      continue;
    }

    const docId = crypto.randomUUID();
    const fileBuffer = doc.buffer;
    const sha256Hash = calculateHash(fileBuffer);
    const signature = signData(fileBuffer, issuer.private_key_pem);

    const aadString = buildEnvelopeAad({
      docId,
      issuerId: issuer.id,
      originalFilename: doc.filename,
    });

    const {
      ivHex,
      authTagHex,
      encryptedBuffer,
      wrappedDekBase64,
      aadBase64,
    } = encryptEnvelopeBuffer(fileBuffer, issuer.public_key_pem, aadString);

    const storageFilename = `${docId}.enc`;
    const storageFilePath = path.join(storageDir, storageFilename);
    fs.writeFileSync(storageFilePath, encryptedBuffer);

    const createdAt = new Date().toISOString();

    insertDocument({
      id: docId,
      title: doc.title,
      originalFilename: doc.filename,
      mimeType: doc.mimeType,
      fileSize: fileBuffer.length,
      sha256Hash,
      signature,
      issuerId: issuer.id,
      issuerName: doc.signerName,
      publicKeyFingerprint: issuer.key_fingerprint,
      storageFilename,
      ivHex,
      authTagHex,
      visibility: doc.visibility,
      keyId: DEFAULT_ACTIVE_KEY_ID,
      wrappedDekBase64,
      aadBase64,
      backupEncryptedBase64: encryptedBuffer.toString('base64'),
      backupSignature: signature,
      backupIvHex: ivHex,
      backupAuthTagHex: authTagHex,
      backupWrappedDekBase64: wrappedDekBase64,
      backupAadBase64: aadBase64,
      backupKeyId: DEFAULT_ACTIVE_KEY_ID,
      createdAt,
    });

    logAuditEvent({
      eventType: 'DOCUMENT_SIGNED_AND_ENCRYPTED',
      severity: 'INFO',
      actor: issuer.username,
      documentId: docId,
      details: {
        title: doc.title,
        originalFilename: doc.filename,
        mimeType: doc.mimeType,
        visibility: doc.visibility,
        sha256Hash,
      },
    });

    console.log(
      `+ Đã ký & mã hóa Word [.docx]: [${doc.filename}] (${doc.visibility}, ${fileBuffer.length} bytes) - ID: ${docId}`
    );

    if (doc.createShare) {
      const shareToken = crypto.randomBytes(24).toString('hex');
      const expiresAt = new Date(Date.now() + doc.shareExpiresHours * 3600 * 1000).toISOString();
      createShareLink({
        token: shareToken,
        documentId: docId,
        createdBy: issuer.username,
        recipientEmail: doc.recipientEmail,
        expiresAt,
        createdAt,
      });
      console.log(`  -> Tạo liên kết chia sẻ cho [${doc.recipientEmail}]: Token = ${shareToken}`);
    }
  }

  syncHashBaselineFile();
  console.log('Hoàn tất khởi tạo dữ liệu Word (.docx) mẫu và đồng bộ baseline hash!');
}

seedSampleDocuments();
