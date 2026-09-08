const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // نضبط توقيت الجلسة يدوياً (يتغيّر مرتين في السنة فقط حسب توقيت مصر الرسمي)
// من أبريل لأكتوبر: +03:00 (صيفي) | من أكتوبر لأبريل: +02:00 (شتوي)
const CAIRO_OFFSET = '+03:00';

pool.on('connection', function (connection) {
  connection.query(`SET time_zone = '${CAIRO_OFFSET}'`);
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error('فشل الاتصال بقاعدة البيانات:', err.message, err.code);
    return;
  }
  console.log('تم الاتصال بقاعدة البيانات بنجاح!');
  connection.release();
});

module.exports = pool;