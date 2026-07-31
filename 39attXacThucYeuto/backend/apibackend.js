const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const path = require('path');

const app = express();
app.use(express.json());

// Phục vụ file tĩnh từ thư mục frontend
app.use(express.static(path.join(__dirname, '../frontend')));

const usersDb = {};

// 1. API Tạo mã QR
app.post('/api/2fa/generate', async (req, res) => {
  try {
    const { userId, email } = req.body;

    const secret = speakeasy.generateSecret({
      length: 20,
      name: `MyWebApp (${email})`
    });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
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

  const verified = speakeasy.totp.verify({
    secret: user.tempSecret,
    encoding: 'base32',
    token: token,
    window: 1
  });

  if (verified) {
    user.secret = user.tempSecret;
    user.is2FAEnabled = true;
    return res.json({ success: true, message: 'Xác thực mã OTP thành công!' });
  }

  res.status(400).json({ success: false, error: 'Mã OTP sai hoặc đã hết hạn' });
});

// BỔ SUNG: Trả về file index.html cho tất cả các request giao diện
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  app.listen(3000, () => {
    console.log('🚀 Server đang chạy tại: http://localhost:3000');
  });
}