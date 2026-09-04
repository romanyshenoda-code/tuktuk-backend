const mysql = require('mysql2');
require('dotenv').config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.on('error', (err) => {
  console.error('خطأ في الاتصال بقاعدة البيانات:', err.message, err.code);
});

connection.connect((err) => {
  if (err) {
    console.error('فشل الاتصال بقاعدة البيانات:', err.message, err.code);
    return;
  }
  console.log('تم الاتصال بقاعدة البيانات بنجاح!');
});

module.exports = connection;
