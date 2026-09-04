const mysql = require('mysql2');
require('dotenv').config();

const connection = mysql.createConnection({
  uri: `mysql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`
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
