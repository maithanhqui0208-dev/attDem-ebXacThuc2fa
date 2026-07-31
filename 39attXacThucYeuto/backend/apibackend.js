const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const path = require('path');

const app = express();
app.use(express.json());

// Đường dẫn trỏ đến thư mục frontend chứa index.html
app.use(express.static(path.join(__dirname, '../frontend')));

const usersDb = {};

// 1. API Tạo mã QR
app.post('/api/2fa/generate', async (req, res) => {
  try {
    const { userId, email } = req.body;

    // Tạo Secret Key ngẫu nhiên
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `MyWebApp (${email})`
    });

    // Tạo QR Code dưới dạng Data URL (mã hóa Base64)
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Lưu lại secret dạng base32
    usersDb[userId] = { email, tempSecret: secret.base32, is2FAEnabled: false };

    res.json({ secret: secret.base32, qrCodeUrl });
  } catch (error) {
    res.status(500).json({ error: 'Lỗi tạo mã QR' });
  }
});

// 2. API Xác thực mã OTP
app.post('/api/2fa/verify', (req, res) => {
  const { userId, token } = req.body;
  const user = usersDb[userId];

  if (!user || !user.tempSecret) {
    return res.status(400).json({ success: false, error: 'Chưa tạo mã QR' });
  }

  // Xác minh mã OTP bằng speakeasy
  const verified = speakeasy.totp.verify({
    secret: user.tempSecret,
    encoding: 'base32',
    token: token,
    window: 1 // Chênh lệch thời gian ±30 giây
  });

  if (verified) {
    user.secret = user.tempSecret;
    user.is2FAEnabled = true;
    return res.json({ success: true, message: 'Xác thực mã OTP thành công!' });
  }

  res.status(400).json({ success: false, error: 'Mã OTP sai hoặc đã hết hạn' });
});
// Thêm module.exports ở cuối file
module.exports = app;

// Chỉ chạy app.listen() khi ở môi trường Local
if (process.env.NODE_ENV !== 'production') {
  app.listen(3000, () => {
    console.log('🚀 Server đang chạy tại: http://localhost:3000');
  });
}