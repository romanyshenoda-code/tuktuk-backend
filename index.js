const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;

app.use(express.json());

const storage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/'); },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const upload = multer({ storage: storage });
app.use('/uploads', express.static('uploads'));

function getSetting(key, callback) {
  db.query('SELECT setting_value FROM system_settings WHERE setting_key = ?', [key], (err, results) => {
    if (err || results.length === 0) return callback(null, 'false');
    callback(null, results[0].setting_value);
  });
}

app.use(session({
  secret: 'tuktuk-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 }
}));

// ==================== تسجيل دخول الأدمن ====================
function requireLogin(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  return res.redirect('/login.html');
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM admins WHERE username = ? AND password = ?', [username, password], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' }); }
    if (results.length === 0) return res.status(401).json({ error: 'اسم المستخدم أو الباسورد غلط' });
    req.session.loggedIn = true;
    req.session.adminId = results[0].id;
    req.session.adminName = results[0].name;
    res.json({ message: 'تم تسجيل الدخول بنجاح' });
  });
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// ==================== إدارة الأدمنية ====================
app.get('/admins', (req, res) => {
  db.query('SELECT id, name, username, created_at FROM admins', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأدمنية' }); }
    res.json(results);
  });
});

app.post('/admins', (req, res) => {
  const { name, username, password } = req.body;
  db.query('INSERT INTO admins (name, username, password) VALUES (?, ?, ?)', [name, username, password], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'اسم المستخدم ده مستخدم بالفعل' });
      console.error(err); return res.status(500).json({ error: 'حصل خطأ في إضافة الأدمن' });
    }
    res.status(201).json({ message: 'تم إضافة الأدمن بنجاح', admin_id: result.insertId });
  });
});

app.put('/admins/:id', (req, res) => {
  const { id } = req.params;
  const { name, username } = req.body;
  db.query('UPDATE admins SET name = ?, username = ? WHERE id = ?', [name, username, id], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'اسم المستخدم ده مستخدم بالفعل' });
      console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الأدمن' });
    }
    res.json({ message: 'تم تحديث بيانات الأدمن بنجاح' });
  });
});

app.put('/admins/:id/password', (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  db.query('UPDATE admins SET password = ? WHERE id = ?', [password, id], (err) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الباسورد' }); }
    res.json({ message: 'تم تغيير الباسورد بنجاح' });
  });
});

app.delete('/admins/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT COUNT(*) AS total FROM admins', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ' }); }
    if (results[0].total <= 1) return res.status(400).json({ error: 'مينفعش تمسح آخر أدمن في النظام' });
    db.query('DELETE FROM admins WHERE id = ?', [id], (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف الأدمن' }); }
      res.json({ message: 'تم حذف الأدمن بنجاح' });
    });
  });
});

// ==================== تسجيل دخول السائق ====================
app.post('/api/driver-login', (req, res) => {
  const { driver_id, password } = req.body;
  db.query('SELECT * FROM drivers WHERE id = ? AND password = ?', [driver_id, password], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' }); }
    if (results.length === 0) return res.status(401).json({ error: 'رقم السائق أو الباسورد غلط' });
    req.session.driverId = results[0].id;
    req.session.driverName = results[0].name;
    res.json({ message: 'تم تسجيل الدخول بنجاح', driver: results[0] });
  });
});

app.get('/api/driver-logout', (req, res) => {
  req.session.driverId = null;
  req.session.driverName = null;
  res.redirect('/driver-login.html');
});

app.get('/api/driver-session', (req, res) => {
  if (req.session && req.session.driverId) {
    res.json({ loggedIn: true, driverId: req.session.driverId, driverName: req.session.driverName });
  } else {
    res.json({ loggedIn: false });
  }
});

// ==================== تسجيل دخول قسم المالية ====================
function requireFinanceLogin(req, res, next) {
  if (req.session && req.session.financeLoggedIn) return next();
  return res.redirect('/finance-login.html');
}

app.post('/api/finance-login', (req, res) => {
  const { password } = req.body;
  db.query('SELECT * FROM finance_admin WHERE password = ?', [password], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' }); }
    if (results.length === 0) return res.status(401).json({ error: 'الباسورد غلط' });
    req.session.financeLoggedIn = true;
    res.json({ message: 'تم تسجيل الدخول بنجاح' });
  });
});

app.get('/api/finance-logout', (req, res) => {
  req.session.financeLoggedIn = false;
  res.redirect('/finance-login.html');
});

app.get('/api/finance-session', (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.financeLoggedIn) });
});

// ==================== الصفحات المحمية ====================
app.get('/', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/finance.html', requireFinanceLogin, (req, res) => {
  res.sendFile(__dirname + '/public/finance.html');
});

app.use(express.static('public'));

// ==================== إعدادات الصور ====================
app.get('/settings', (req, res) => {
  db.query('SELECT setting_key, setting_value FROM system_settings', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
    res.json(results);
  });
});

app.put('/settings/:key', (req, res) => {
  const { key } = req.params;
  const { value } = req.body;
  db.query('UPDATE system_settings SET setting_value = ? WHERE setting_key = ?', [value, key], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الإعداد' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الإعداد غير موجود' });
    res.json({ message: 'تم تحديث الإعداد بنجاح' });
  });
});

// ==================== السواقين ====================
app.post('/drivers', (req, res) => {
  const { name, phone, national_id, password } = req.body;
  db.query('INSERT INTO drivers (name, phone, national_id, password) VALUES (?, ?, ?, ?)', [name, phone, national_id, password], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حفظ السائق' }); }
    res.status(201).json({ message: 'تم تسجيل السائق بنجاح', driver_id: result.insertId });
  });
});

app.get('/drivers', (req, res) => {
  db.query('SELECT * FROM drivers', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب السواقين' }); }
    res.json(results);
  });
});

app.put('/drivers/:id', (req, res) => {
  const { id } = req.params;
  const { name, phone, national_id } = req.body;
  db.query('UPDATE drivers SET name = ?, phone = ?, national_id = ? WHERE id = ?', [name, phone, national_id, id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث بيانات السائق' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'السائق غير موجود' });
    res.json({ message: 'تم تحديث بيانات السائق بنجاح' });
  });
});

app.put('/drivers/:id/password', (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'من فضلك ابعت الباسورد الجديد' });
  db.query('UPDATE drivers SET password = ? WHERE id = ?', [password, id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الباسورد' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'السائق غير موجود' });
    res.json({ message: 'تم تغيير الباسورد بنجاح' });
  });
});

// ==================== تخصيص سائق (الإصدار الجديد بنسبتي عمولة منفصلتين) ====================
app.put('/drivers/:id/customize', (req, res) => {
  const { id } = req.params;
  const {
    is_customized, custom_income_type, custom_monthly_salary,
    custom_delivery_commission_pct, custom_full_trip_commission_pct,
    custom_delivery_base_price, custom_full_trip_base_price,
    custom_working_days, custom_weekly_rest_days, custom_personal_leave_balance
  } = req.body;

  if (is_customized && custom_working_days && custom_weekly_rest_days) {
    const restDaysArray = custom_weekly_rest_days.split(',').map(d => d.trim()).filter(Boolean);
    const restDaysPerWeek = restDaysArray.length;
    const expectedRestDays = Math.round(restDaysPerWeek * (30 / 7));
    const computedWorkingDays = 30 - expectedRestDays;
    const enteredWorkingDays = parseInt(custom_working_days);

    if (Math.abs(computedWorkingDays - enteredWorkingDays) > 1) {
      return res.status(400).json({
        error: `عدد أيام الراحة المخصصة (${restDaysPerWeek} أيام أسبوعياً) بيدّي تقريباً ${computedWorkingDays} يوم عمل، مش ${enteredWorkingDays}. عدّل العدد أو الأيام.`
      });
    }
  }

  db.query(
    `UPDATE drivers SET
      is_customized = ?, custom_income_type = ?, custom_monthly_salary = ?,
      custom_delivery_commission_pct = ?, custom_full_trip_commission_pct = ?,
      custom_delivery_base_price = ?, custom_full_trip_base_price = ?,
      custom_working_days = ?, custom_weekly_rest_days = ?, custom_personal_leave_balance = ?
     WHERE id = ?`,
    [
      is_customized, custom_income_type, custom_monthly_salary,
      custom_delivery_commission_pct, custom_full_trip_commission_pct,
      custom_delivery_base_price, custom_full_trip_base_price,
      custom_working_days, custom_weekly_rest_days, custom_personal_leave_balance,
      id
    ],
    (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث التخصيص' }); }
      res.json({ message: 'تم تحديث تخصيص السائق بنجاح' });
    }
  );
});

app.delete('/drivers/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM drivers WHERE id = ?', [id], (err, result) => {
    if (err) {
      if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
        return res.status(400).json({ error: 'مينفعش تمسح السائق ده لأن عنده ورديات أو أوردرات أو طلبات مسجلة' });
      }
      console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف السائق' });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'السائق غير موجود' });
    res.json({ message: 'تم حذف السائق نهائياً' });
  });
});

// ==================== التوكتوكات ====================
app.post('/tuktuks', (req, res) => {
  const { tuktuk_number, qr_code } = req.body;
  db.query('INSERT INTO tuktuks (tuktuk_number, qr_code) VALUES (?, ?)', [tuktuk_number, qr_code], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل التوكتوك' }); }
    res.status(201).json({ message: 'تم تسجيل التوكتوك بنجاح', tuktuk_id: result.insertId });
  });
});

app.get('/tuktuks', (req, res) => {
  db.query('SELECT * FROM tuktuks', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب التوكتوكات' }); }
    res.json(results);
  });
});

app.put('/tuktuks/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['active', 'maintenance'].includes(status)) return res.status(400).json({ error: 'حالة غير صحيحة' });
  db.query('UPDATE tuktuks SET status = ? WHERE id = ?', [status, id], (err) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث حالة التوكتوك' }); }
    res.json({ message: 'تم تحديث حالة التوكتوك بنجاح' });
  });
});

app.delete('/tuktuks/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM tuktuks WHERE id = ?', [id], (err, result) => {
    if (err) {
      if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
        return res.status(400).json({ error: 'مينفعش تمسح التوكتوك ده لأن عنده ورديات مسجلة بالفعل' });
      }
      console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف التوكتوك' });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'التوكتوك غير موجود' });
    res.json({ message: 'تم حذف التوكتوك نهائياً' });
  });
});

// ==================== مواقع الحضور ====================
app.post('/admin-locations', (req, res) => {
  const { name, latitude, longitude, radius_meters } = req.body;
  db.query('INSERT INTO admin_locations (name, latitude, longitude, radius_meters) VALUES (?, ?, ?, ?)', [name, latitude, longitude, radius_meters || 100], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الموقع' }); }
    res.status(201).json({ message: 'تم تسجيل الموقع بنجاح', location_id: result.insertId });
  });
});

// ==================== الحضور ====================
app.post('/shifts/check-in', upload.single('photo'), (req, res) => {
  const { driver_id, tuktuk_qr_code, lat, lng } = req.body;
  const photo = req.file ? req.file.filename : null;

  getSetting('photo_required_checkin', (err, required) => {
    if (required === 'true' && !photo) return res.status(400).json({ error: 'الصورة إجبارية عند تسجيل الحضور' });

    db.query('SELECT id FROM tuktuks WHERE qr_code = ?', [tuktuk_qr_code], (err, tuktukResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في البحث عن التوكتوك' }); }
      if (tuktukResults.length === 0) return res.status(404).json({ error: 'كود QR غير معروف' });

      const tuktuk_id = tuktukResults[0].id;
      db.query(
        `INSERT INTO shifts (driver_id, tuktuk_id, check_in_time, check_in_photo, check_in_lat, check_in_lng, status) VALUES (?, ?, NOW(), ?, ?, ?, 'open')`,
        [driver_id, tuktuk_id, photo, lat, lng],
        (err, result) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الحضور' }); }
          res.status(201).json({ message: 'تم تسجيل الحضور بنجاح', shift_id: result.insertId, tuktuk_id });
        }
      );
    });
  });
});

app.post('/shifts/check-out', upload.single('photo'), (req, res) => {
  const { shift_id } = req.body;
  const photo = req.file ? req.file.filename : null;

  getSetting('photo_required_checkout', (err, required) => {
    if (required === 'true' && !photo) return res.status(400).json({ error: 'الصورة إجبارية عند تسجيل الانصراف' });

    db.query(
      `UPDATE shifts SET check_out_time = NOW(), check_out_photo = ?, status = 'closed' WHERE id = ? AND status = 'open'`,
      [photo, shift_id],
      (err, result) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الانصراف' }); }
        if (result.affectedRows === 0) return res.status(404).json({ error: 'الوردية غير موجودة أو مقفولة بالفعل' });
        res.json({ message: 'تم تسجيل الانصراف بنجاح' });
      }
    );
  });
});

app.post('/shifts/change-tuktuk', (req, res) => {
  const { driver_id, new_tuktuk_qr_code } = req.body;
  db.query('SELECT id, tuktuk_id FROM shifts WHERE driver_id = ? AND status = "open"', [driver_id], (err, shiftResults) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في البحث عن الوردية' }); }
    if (shiftResults.length === 0) return res.status(404).json({ error: 'مفيش وردية مفتوحة أصلاً عشان تغيّر توكتوكها' });

    const shift_id = shiftResults[0].id;
    const current_tuktuk_id = shiftResults[0].tuktuk_id;

    db.query('SELECT id FROM tuktuks WHERE qr_code = ?', [new_tuktuk_qr_code], (err, tuktukResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في البحث عن التوكتوك' }); }
      if (tuktukResults.length === 0) return res.status(404).json({ error: 'كود QR غير معروف' });

      const new_tuktuk_id = tuktukResults[0].id;
      if (new_tuktuk_id === current_tuktuk_id) {
        return res.status(400).json({ error: 'ده نفس التوكتوك المسجل عليك بالفعل، مفيش داعي تغيّره' });
      }

      db.query('UPDATE shifts SET tuktuk_id = ? WHERE id = ?', [new_tuktuk_id, shift_id], (err) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث التوكتوك' }); }
        res.json({ message: 'تم تغيير التوكتوك بنجاح', shift_id, new_tuktuk_id });
      });
    });
  });
});

app.delete('/shifts/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM shifts WHERE id = ?', [id], (err, result) => {
    if (err) {
      if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.code === 'ER_ROW_IS_REFERENCED') {
        return res.status(400).json({ error: 'مينفعش تمسح الوردية دي لأن فيها أوردرات مسجلة عليها. احذف الأوردرات الأول.' });
      }
      console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف الوردية' });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الوردية غير موجودة' });
    res.json({ message: 'تم حذف الوردية نهائياً' });
  });
});

// ==================== الأوردرات ====================
app.post('/orders/open', (req, res) => {
  const { shift_id, driver_id, order_type, start_lat, start_lng } = req.body;
  db.query('SELECT id FROM orders WHERE driver_id = ? AND status = "open"', [driver_id], (err, openResults) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في التحقق من الأوردرات' }); }
    if (openResults.length > 0) return res.status(400).json({ error: 'السائق عنده أوردر مفتوح بالفعل، لازم يقفله الأول' });

    db.query('SELECT driver_commission_pct FROM pricing_rules WHERE order_type = ? ORDER BY effective_from DESC LIMIT 1', [order_type], (err, pricingResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب التسعيرة' }); }
      if (pricingResults.length === 0) return res.status(400).json({ error: 'مفيش تسعيرة محددة لنوع الرحلة ده' });

      const commission_pct = pricingResults[0].driver_commission_pct;
      db.query(
        `INSERT INTO orders (shift_id, driver_id, order_type, start_lat, start_lng, start_time, driver_commission_pct, status) VALUES (?, ?, ?, ?, ?, NOW(), ?, 'open')`,
        [shift_id, driver_id, order_type, start_lat, start_lng, commission_pct],
        (err, result) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في فتح الأوردر' }); }
          res.status(201).json({ message: 'تم فتح الأوردر بنجاح', order_id: result.insertId });
        }
      );
    });
  });
});

function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

app.post('/orders/close', upload.single('photo'), (req, res) => {
  const { order_id, end_lat, end_lng } = req.body;
  const photo = req.file ? req.file.filename : null;

  getSetting('photo_required_order_close', (err, required) => {
    if (required === 'true' && !photo) return res.status(400).json({ error: 'الصورة إجبارية عند قفل الأوردر' });

    db.query('SELECT * FROM orders WHERE id = ? AND status = "open"', [order_id], (err, orderResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأوردر' }); }
      if (orderResults.length === 0) return res.status(404).json({ error: 'الأوردر غير موجود أو مقفول بالفعل' });

      const order = orderResults[0];
      const distance_km = calculateDistance(order.start_lat, order.start_lng, end_lat, end_lng);

      db.query('SELECT * FROM pricing_rules WHERE order_type = ? ORDER BY effective_from DESC LIMIT 1', [order.order_type], (err, pricingResults) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب التسعيرة' }); }
        const pricing = pricingResults[0];
        let price = 0;
        if (order.order_type === 'delivery') price = distance_km * pricing.price_per_km;
        else if (order.order_type === 'full_trip') price = pricing.price_per_day;

        const driver_earning = price * (order.driver_commission_pct / 100);

        db.query(
          `UPDATE orders SET end_lat = ?, end_lng = ?, end_time = NOW(), distance_km = ?, price = ?, driver_earning = ?, status = 'closed', delivery_photo = ? WHERE id = ?`,
          [end_lat, end_lng, distance_km.toFixed(2), price.toFixed(2), driver_earning.toFixed(2), photo, order_id],
          (err) => {
            if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في قفل الأوردر' }); }
            res.json({ message: 'تم قفل الأوردر بنجاح', distance_km: distance_km.toFixed(2), price: price.toFixed(2), driver_earning: driver_earning.toFixed(2) });
          }
        );
      });
    });
  });
});

app.post('/orders/:id/cancel', (req, res) => {
  const { id } = req.params;
  db.query('UPDATE orders SET status = "cancelled" WHERE id = ? AND status = "open"', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في إلغاء الأوردر' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الأوردر غير موجود أو مقفول بالفعل' });
    res.json({ message: 'تم إلغاء الأوردر بنجاح' });
  });
});

app.delete('/orders/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM orders WHERE id = ?', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف الأوردر' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الأوردر غير موجود' });
    res.json({ message: 'تم حذف الأوردر نهائياً' });
  });
});

app.get('/orders/active', (req, res) => {
  db.query(
    `SELECT orders.*, drivers.name AS driver_name FROM orders JOIN drivers ON orders.driver_id = drivers.id WHERE orders.status = 'open' ORDER BY orders.start_time DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأوردرات الشغالة' }); }
      res.json(results);
    }
  );
});

// ==================== ملخص الوردية ====================
app.post('/shifts/:shift_id/summary', (req, res) => {
  const { shift_id } = req.params;
  db.query('SELECT * FROM orders WHERE shift_id = ? AND status = "closed"', [shift_id], (err, orders) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب أوردرات الوردية' }); }

    const total_orders = orders.length;
    const full_trip_count = orders.filter(o => o.order_type === 'full_trip').length;
    const delivery_count = orders.filter(o => o.order_type === 'delivery').length;
    const total_price = orders.reduce((sum, o) => sum + parseFloat(o.price || 0), 0);
    const total_driver_earning = orders.reduce((sum, o) => sum + parseFloat(o.driver_earning || 0), 0);

    db.query(
      `INSERT INTO shift_summary (shift_id, total_orders, full_trip_count, delivery_count, total_price, total_driver_earning) VALUES (?, ?, ?, ?, ?, ?)`,
      [shift_id, total_orders, full_trip_count, delivery_count, total_price.toFixed(2), total_driver_earning.toFixed(2)],
      (err, result) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حفظ الملخص' }); }
        res.status(201).json({ message: 'تم إنشاء ملخص الوردية بنجاح', summary_id: result.insertId, total_orders, full_trip_count, delivery_count, total_price: total_price.toFixed(2), total_driver_earning: total_driver_earning.toFixed(2) });
      }
    );
  });
});

app.put('/shift-summary/:id', (req, res) => {
  const { id } = req.params;
  const { field_name, new_value, admin_id } = req.body;
  const allowedFields = ['total_orders', 'full_trip_count', 'delivery_count', 'total_price', 'total_driver_earning'];
  if (!allowedFields.includes(field_name)) return res.status(400).json({ error: 'الحقل ده مش مسموح تعديله' });

  db.query(`SELECT ${field_name} AS old_value FROM shift_summary WHERE id = ?`, [id], (err, oldResults) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب البيانات' }); }
    if (oldResults.length === 0) return res.status(404).json({ error: 'الملخص غير موجود' });

    const old_value = oldResults[0].old_value;
    db.query(`UPDATE shift_summary SET ${field_name} = ?, is_manually_edited = TRUE, edited_by = ?, edited_at = NOW() WHERE id = ?`, [new_value, admin_id, id], (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في التعديل' }); }
      db.query(
        `INSERT INTO audit_logs (entity_type, entity_id, admin_id, field_name, old_value, new_value) VALUES ('shift_summary', ?, ?, ?, ?, ?)`,
        [id, admin_id, field_name, old_value, new_value],
        (err) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل السجل' }); }
          res.json({ message: 'تم التعديل وتسجيله بنجاح', field_name, old_value, new_value });
        }
      );
    });
  });
});

// ==================== جلب البيانات العامة ====================
app.get('/shifts', (req, res) => {
  db.query(
    `SELECT shifts.*, drivers.name AS driver_name, tuktuks.tuktuk_number FROM shifts JOIN drivers ON shifts.driver_id = drivers.id JOIN tuktuks ON shifts.tuktuk_id = tuktuks.id ORDER BY shifts.check_in_time DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الورديات' }); }
      res.json(results);
    }
  );
});

app.get('/orders', (req, res) => {
  db.query(
    `SELECT orders.*, drivers.name AS driver_name FROM orders JOIN drivers ON orders.driver_id = drivers.id ORDER BY orders.start_time DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأوردرات' }); }
      res.json(results);
    }
  );
});

app.get('/shift-summaries', (req, res) => {
  db.query(
    `SELECT shift_summary.*, drivers.name AS driver_name FROM shift_summary JOIN shifts ON shift_summary.shift_id = shifts.id JOIN drivers ON shifts.driver_id = drivers.id ORDER BY shift_summary.created_at DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الملخصات' }); }
      res.json(results);
    }
  );
});

app.get('/shifts/open/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM shifts WHERE driver_id = ? AND status = "open"', [driver_id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في البحث عن الوردية' }); }
    if (results.length === 0) return res.status(404).json({ error: 'مفيش وردية مفتوحة للسائق ده' });
    res.json(results[0]);
  });
});

app.get('/shifts/history/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query(
    `SELECT shifts.*, tuktuks.tuktuk_number FROM shifts JOIN tuktuks ON shifts.tuktuk_id = tuktuks.id WHERE shifts.driver_id = ? ORDER BY shifts.check_in_time DESC LIMIT 10`,
    [driver_id],
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب سجل الورديات' }); }
      res.json(results);
    }
  );
});

app.get('/orders/history/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query(
    `SELECT * FROM orders WHERE driver_id = ? AND status = 'closed' ORDER BY start_time DESC LIMIT 20`,
    [driver_id],
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب سجل الأوردرات' }); }
      res.json(results);
    }
  );
});

// ==================== طلبات الإجازة ====================
app.post('/leave-requests', (req, res) => {
  const { driver_id, start_date, end_date, reason } = req.body;
  db.query('INSERT INTO leave_requests (driver_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)', [driver_id, start_date, end_date, reason], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل طلب الإجازة' }); }
    res.status(201).json({ message: 'تم إرسال طلب الإجازة بنجاح', request_id: result.insertId });
  });
});

app.get('/leave-requests', (req, res) => {
  db.query(
    `SELECT leave_requests.*, drivers.name AS driver_name FROM leave_requests JOIN drivers ON leave_requests.driver_id = drivers.id ORDER BY leave_requests.created_at DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب طلبات الإجازة' }); }
      res.json(results);
    }
  );
});

app.get('/leave-requests/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM leave_requests WHERE driver_id = ? ORDER BY created_at DESC', [driver_id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب طلبات الإجازة' }); }
    res.json(results);
  });
});

app.put('/leave-requests/:id', (req, res) => {
  const { id } = req.params;
  const { status, admin_note } = req.body;
  db.query('SELECT * FROM leave_requests WHERE id = ?', [id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الطلب' }); }
    if (results.length === 0) return res.status(404).json({ error: 'الطلب غير موجود' });

    const request = results[0];
    db.query('UPDATE leave_requests SET status = ?, admin_note = ?, reviewed_at = NOW() WHERE id = ?', [status, admin_note, id], (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الطلب' }); }
      const statusText = status === 'approved' ? 'تمت الموافقة' : 'تم الرفض';
      const message = `طلب الإجازة الخاص بك من ${request.start_date} إلى ${request.end_date}: ${statusText}${admin_note ? ' - ' + admin_note : ''}`;
      db.query('INSERT INTO notifications (driver_id, message) VALUES (?, ?)', [request.driver_id, message], (err) => {
        if (err) console.error(err);
        res.json({ message: 'تم تحديث حالة الطلب بنجاح' });
      });
    });
  });
});

// ==================== طلبات السلف ====================
app.post('/advances', (req, res) => {
  const { driver_id, amount, reason } = req.body;
  db.query('INSERT INTO advances (driver_id, amount, reason) VALUES (?, ?, ?)', [driver_id, amount, reason], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل طلب السلفة' }); }
    res.status(201).json({ message: 'تم إرسال طلب السلفة بنجاح', request_id: result.insertId });
  });
});

app.get('/advances', (req, res) => {
  db.query(
    `SELECT advances.*, drivers.name AS driver_name FROM advances JOIN drivers ON advances.driver_id = drivers.id ORDER BY advances.created_at DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب طلبات السلف' }); }
      res.json(results);
    }
  );
});

app.get('/advances/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM advances WHERE driver_id = ? ORDER BY created_at DESC', [driver_id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب طلبات السلف' }); }
    res.json(results);
  });
});

app.put('/advances/:id', (req, res) => {
  const { id } = req.params;
  const { status, admin_note } = req.body;
  db.query('SELECT * FROM advances WHERE id = ?', [id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الطلب' }); }
    if (results.length === 0) return res.status(404).json({ error: 'الطلب غير موجود' });

    const request = results[0];
    db.query('UPDATE advances SET status = ?, admin_note = ?, reviewed_at = NOW() WHERE id = ?', [status, admin_note, id], (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الطلب' }); }
      const statusText = status === 'approved' ? 'تمت الموافقة' : 'تم الرفض';
      const message = `طلب السلفة بمبلغ ${request.amount} جنيه: ${statusText}${admin_note ? ' - ' + admin_note : ''}`;
      db.query('INSERT INTO notifications (driver_id, message) VALUES (?, ?)', [request.driver_id, message], (err) => {
        if (err) console.error(err);
        res.json({ message: 'تم تحديث حالة الطلب بنجاح' });
      });
    });
  });
});

// ==================== الخصومات ====================
app.post('/deductions', (req, res) => {
  const { driver_id, amount, reason } = req.body;
  db.query('INSERT INTO deductions (driver_id, amount, reason) VALUES (?, ?, ?)', [driver_id, amount, reason], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الخصم' }); }
    const message = `تم تسجيل خصم بمبلغ ${amount} جنيه - السبب: ${reason}`;
    db.query('INSERT INTO notifications (driver_id, message) VALUES (?, ?)', [driver_id, message], (err) => {
      if (err) console.error(err);
      res.status(201).json({ message: 'تم تسجيل الخصم بنجاح', deduction_id: result.insertId });
    });
  });
});

app.get('/deductions/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM deductions WHERE driver_id = ? ORDER BY created_at DESC', [driver_id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الخصومات' }); }
    res.json(results);
  });
});

// ==================== الإشعارات ====================
app.get('/notifications/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM notifications WHERE driver_id = ? ORDER BY created_at DESC LIMIT 20', [driver_id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإشعارات' }); }
    res.json(results);
  });
});

app.put('/notifications/:id/read', (req, res) => {
  const { id } = req.params;
  db.query('UPDATE notifications SET is_read = TRUE WHERE id = ?', [id], (err) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الإشعار' }); }
    res.json({ message: 'تم' });
  });
});

// ==================== إعدادات الرواتب العامة (بنسبتي عمولة منفصلتين) ====================
app.get('/payroll-settings', (req, res) => {
  db.query('SELECT * FROM payroll_settings ORDER BY id DESC LIMIT 1', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
    res.json(results[0] || {});
  });
});

app.put('/payroll-settings', (req, res) => {
  const { income_type, monthly_salary, delivery_commission_pct, full_trip_commission_pct, delivery_base_price, full_trip_base_price } = req.body;
  db.query(
    'UPDATE payroll_settings SET income_type = ?, monthly_salary = ?, delivery_commission_pct = ?, full_trip_commission_pct = ?, delivery_base_price = ?, full_trip_base_price = ? WHERE id = 1',
    [income_type, monthly_salary, delivery_commission_pct, full_trip_commission_pct, delivery_base_price, full_trip_base_price],
    (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الإعدادات' }); }
      res.json({ message: 'تم تحديث الإعدادات العامة بنجاح' });
    }
  );
});

// ==================== إعدادات الإجازات العامة ====================
app.get('/leave-config', (req, res) => {
  db.query('SELECT * FROM leave_config ORDER BY id DESC LIMIT 1', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب إعدادات الإجازات' }); }
    res.json(results[0] || {});
  });
});

app.put('/leave-config', (req, res) => {
  const { working_days_per_month, weekly_rest_days, personal_leave_balance } = req.body;

  const restDaysArray = (weekly_rest_days || '').split(',').map(d => d.trim()).filter(Boolean);
  const restDaysPerWeek = restDaysArray.length;
  const expectedRestDays = Math.round(restDaysPerWeek * (30 / 7));
  const computedWorkingDays = 30 - expectedRestDays;
  const enteredWorkingDays = parseInt(working_days_per_month);

  if (Math.abs(computedWorkingDays - enteredWorkingDays) > 1) {
    return res.status(400).json({
      error: `عدد أيام الراحة اللي اخترتها (${restDaysPerWeek} أيام أسبوعياً) بيدّي تقريباً ${computedWorkingDays} يوم عمل بالشهر، مش ${enteredWorkingDays}. من فضلك عدّل العدد أو أيام الراحة عشان يتطابقوا.`
    });
  }

  db.query(
    'UPDATE leave_config SET working_days_per_month = ?, weekly_rest_days = ?, personal_leave_balance = ? WHERE id = 1',
    [working_days_per_month, weekly_rest_days, personal_leave_balance],
    (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث إعدادات الإجازات' }); }
      res.json({ message: 'تم تحديث إعدادات الإجازات بنجاح' });
    }
  );
});

// ==================== المناسبات الجماعية ====================
app.post('/holiday-events', (req, res) => {
  const { event_name, start_date, end_date, driver_ids } = req.body;
  db.query('INSERT INTO holiday_events (event_name, start_date, end_date) VALUES (?, ?, ?)', [event_name, start_date, end_date], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل المناسبة' }); }
    const event_id = result.insertId;

    if (!driver_ids || driver_ids.length === 0) {
      return res.status(201).json({ message: 'تم تسجيل المناسبة بنجاح بدون سواقين' });
    }

    const values = driver_ids.map(driver_id => [event_id, driver_id]);
    db.query('INSERT INTO holiday_event_drivers (holiday_event_id, driver_id) VALUES ?', [values], (err) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في ربط السواقين بالمناسبة' }); }
      driver_ids.forEach(driver_id => {
        const message = `تم تسجيل إجازة "${event_name}" لك من ${start_date} إلى ${end_date} بمرتب كامل`;
        db.query('INSERT INTO notifications (driver_id, message) VALUES (?, ?)', [driver_id, message]);
      });
      res.status(201).json({ message: 'تم تسجيل المناسبة بنجاح لكل السواقين المحددين', event_id });
    });
  });
});

app.get('/holiday-events', (req, res) => {
  db.query('SELECT * FROM holiday_events ORDER BY start_date DESC', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب المناسبات' }); }
    res.json(results);
  });
});

app.get('/holiday-events/:id/drivers', (req, res) => {
  const { id } = req.params;
  db.query(
    `SELECT hed.driver_id, drivers.name FROM holiday_event_drivers hed JOIN drivers ON hed.driver_id = drivers.id WHERE hed.holiday_event_id = ?`,
    [id],
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب سواقين المناسبة' }); }
      res.json(results);
    }
  );
});

app.delete('/holiday-events/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM holiday_events WHERE id = ?', [id], (err) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف المناسبة' }); }
    res.json({ message: 'تم حذف المناسبة نهائياً' });
  });
});

function getHolidayDaysForDriver(driver_id, year, month, callback) {
  const query = `
    SELECT he.start_date, he.end_date
    FROM holiday_events he
    JOIN holiday_event_drivers hed ON he.id = hed.holiday_event_id
    WHERE hed.driver_id = ?
    AND (
      (YEAR(he.start_date) = ? AND MONTH(he.start_date) = ?)
      OR (YEAR(he.end_date) = ? AND MONTH(he.end_date) = ?)
    )
  `;
  db.query(query, [driver_id, year, month, year, month], (err, results) => {
    if (err) return callback(err, 0);
    let totalDays = 0;
    results.forEach(h => {
      const start = new Date(h.start_date);
      const end = new Date(h.end_date);
      const diffDays = Math.floor((end - start) / (1000 * 60 * 60 * 24)) + 1;
      totalDays += diffDays;
    });
    callback(null, totalDays);
  });
}

// ==================== حساب راتب سائق لشهر معين (بنسبتي عمولة منفصلتين) ====================
app.get('/payroll/calculate/:driver_id/:year/:month', (req, res) => {
  const { driver_id, year, month } = req.params;

  db.query('SELECT * FROM drivers WHERE id = ?', [driver_id], (err, driverResults) => {
    if (err || driverResults.length === 0) return res.status(404).json({ error: 'السائق غير موجود' });
    const driver = driverResults[0];

    db.query('SELECT * FROM payroll_settings ORDER BY id DESC LIMIT 1', (err, settingsResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
      const settings = settingsResults[0];

      db.query('SELECT * FROM leave_config ORDER BY id DESC LIMIT 1', (err, leaveConfigResults) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب إعدادات الإجازات' }); }
        const leaveConfig = leaveConfigResults[0];

        const income_type = driver.is_customized ? driver.custom_income_type : settings.income_type;
        const monthly_salary = driver.is_customized ? driver.custom_monthly_salary : settings.monthly_salary;
        const delivery_commission_pct = driver.is_customized ? driver.custom_delivery_commission_pct : settings.delivery_commission_pct;
        const full_trip_commission_pct = driver.is_customized ? driver.custom_full_trip_commission_pct : settings.full_trip_commission_pct;
        const delivery_base_price = driver.is_customized ? driver.custom_delivery_base_price : settings.delivery_base_price;
        const full_trip_base_price = driver.is_customized ? driver.custom_full_trip_base_price : settings.full_trip_base_price;
        const baseWorkingDays = driver.is_customized ? driver.custom_working_days : leaveConfig.working_days_per_month;

        getHolidayDaysForDriver(driver_id, year, month, (err, holidayDaysCount) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب أيام الأعياد' }); }

          const requiredWorkingDays = Math.max(baseWorkingDays - holidayDaysCount, 0);

          db.query(
            `SELECT COUNT(DISTINCT DATE(check_in_time)) AS days_present FROM shifts WHERE driver_id = ? AND YEAR(check_in_time) = ? AND MONTH(check_in_time) = ?`,
            [driver_id, year, month],
            (err, attendanceResults) => {
              if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الحضور' }); }
              const days_present = attendanceResults[0].days_present || 0;

              db.query(
                `SELECT order_type, COUNT(*) AS count FROM orders WHERE driver_id = ? AND status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ? GROUP BY order_type`,
                [driver_id, year, month],
                (err, ordersCountResults) => {
                  if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الأوردرات' }); }

                  let deliveryCount = 0, fullTripCount = 0;
                  ordersCountResults.forEach(r => {
                    if (r.order_type === 'delivery') deliveryCount = r.count;
                    if (r.order_type === 'full_trip') fullTripCount = r.count;
                  });

                  db.query(
                    `SELECT COALESCE(SUM(price), 0) AS total_revenue FROM orders WHERE driver_id = ? AND status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ?`,
                    [driver_id, year, month],
                    (err, earningsResults) => {
                      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الإيرادات' }); }
                      const total_revenue = parseFloat(earningsResults[0].total_revenue);

                      db.query(
                        `SELECT COALESCE(SUM(amount), 0) AS total_deductions FROM deductions WHERE driver_id = ? AND YEAR(created_at) = ? AND MONTH(created_at) = ?`,
                        [driver_id, year, month],
                        (err, deductionsResults) => {
                          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الخصومات' }); }
                          const total_deductions = parseFloat(deductionsResults[0].total_deductions);

                          db.query(
                            `SELECT COALESCE(SUM(amount), 0) AS total_advances FROM advances WHERE driver_id = ? AND status = 'approved' AND YEAR(created_at) = ? AND MONTH(created_at) = ?`,
                            [driver_id, year, month],
                            (err, advancesResults) => {
                              if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب السلف' }); }
                              const total_advances = parseFloat(advancesResults[0].total_advances);

                              let salaryPart = 0, commissionPart = 0;
                              let deliveryCommission = 0, fullTripCommission = 0;

                              if (income_type === 'salary' || income_type === 'both') {
                                const dailyRate = requiredWorkingDays > 0 ? monthly_salary / requiredWorkingDays : 0;
                                const cappedPresentDays = Math.min(days_present, requiredWorkingDays);
                                salaryPart = dailyRate * cappedPresentDays;
                              }

                              if (income_type === 'commission' || income_type === 'both') {
                                deliveryCommission = deliveryCount * parseFloat(delivery_base_price || 0) * (delivery_commission_pct / 100);
                                fullTripCommission = fullTripCount * parseFloat(full_trip_base_price || 0) * (full_trip_commission_pct / 100);
                                commissionPart = deliveryCommission + fullTripCommission;
                              }

                              const grossPay = salaryPart + commissionPart;
                              const netPay = grossPay - total_deductions - total_advances;

                              res.json({
                                driver_id: parseInt(driver_id),
                                driver_name: driver.name,
                                driver_phone: driver.phone,
                                income_type,
                                days_present,
                                holiday_days: holidayDaysCount,
                                base_working_days: baseWorkingDays,
                                required_working_days: requiredWorkingDays,
                                delivery_count: deliveryCount,
                                full_trip_count: fullTripCount,
                                delivery_commission: deliveryCommission.toFixed(2),
                                full_trip_commission: fullTripCommission.toFixed(2),
                                total_revenue: total_revenue.toFixed(2),
                                salary_part: salaryPart.toFixed(2),
                                commission_part: commissionPart.toFixed(2),
                                gross_pay: grossPay.toFixed(2),
                                total_deductions: total_deductions.toFixed(2),
                                total_advances: total_advances.toFixed(2),
                                net_pay: netPay.toFixed(2)
                              });
                            }
                          );
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        });
      });
    });
  });
});

// ==================== صيانة التوكتوكات ====================
app.post('/tuktuk-maintenance', (req, res) => {
  const { tuktuk_id, driver_id, maintenance_type, description, cost, maintenance_date } = req.body;
  db.query(
    'INSERT INTO tuktuk_maintenance (tuktuk_id, driver_id, maintenance_type, description, cost, maintenance_date) VALUES (?, ?, ?, ?, ?, ?)',
    [tuktuk_id, driver_id || null, maintenance_type, description, cost, maintenance_date],
    (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الصيانة' }); }
      res.status(201).json({ message: 'تم تسجيل مصروف الصيانة بنجاح', id: result.insertId });
    }
  );
});

app.get('/tuktuk-maintenance', (req, res) => {
  db.query(
    `SELECT tuktuk_maintenance.*, tuktuks.tuktuk_number, drivers.name AS driver_name FROM tuktuk_maintenance JOIN tuktuks ON tuktuk_maintenance.tuktuk_id = tuktuks.id LEFT JOIN drivers ON tuktuk_maintenance.driver_id = drivers.id ORDER BY tuktuk_maintenance.maintenance_date DESC`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب سجل الصيانة' }); }
      res.json(results);
    }
  );
});

app.put('/tuktuk-maintenance/:id', (req, res) => {
  const { id } = req.params;
  const { tuktuk_id, driver_id, maintenance_type, description, cost, maintenance_date } = req.body;
  db.query(
    'UPDATE tuktuk_maintenance SET tuktuk_id = ?, driver_id = ?, maintenance_type = ?, description = ?, cost = ?, maintenance_date = ? WHERE id = ?',
    [tuktuk_id, driver_id || null, maintenance_type, description, cost, maintenance_date, id],
    (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث مصروف الصيانة' }); }
      if (result.affectedRows === 0) return res.status(404).json({ error: 'المصروف غير موجود' });
      res.json({ message: 'تم تحديث مصروف الصيانة بنجاح' });
    }
  );
});

app.delete('/tuktuk-maintenance/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM tuktuk_maintenance WHERE id = ?', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف مصروف الصيانة' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'المصروف غير موجود' });
    res.json({ message: 'تم حذف مصروف الصيانة نهائياً' });
  });
});

// ==================== المصروفات العامة ====================
app.post('/general-expenses', (req, res) => {
  const { expense_name, amount, expense_date, notes } = req.body;
  db.query(
    'INSERT INTO general_expenses (expense_name, amount, expense_date, notes) VALUES (?, ?, ?, ?)',
    [expense_name, amount, expense_date, notes],
    (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل المصروف' }); }
      res.status(201).json({ message: 'تم تسجيل المصروف بنجاح', id: result.insertId });
    }
  );
});

app.get('/general-expenses', (req, res) => {
  db.query('SELECT * FROM general_expenses ORDER BY expense_date DESC', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب المصروفات' }); }
    res.json(results);
  });
});

app.put('/general-expenses/:id', (req, res) => {
  const { id } = req.params;
  const { expense_name, amount, expense_date, notes } = req.body;
  db.query(
    'UPDATE general_expenses SET expense_name = ?, amount = ?, expense_date = ?, notes = ? WHERE id = ?',
    [expense_name, amount, expense_date, notes, id],
    (err, result) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث المصروف' }); }
      if (result.affectedRows === 0) return res.status(404).json({ error: 'المصروف غير موجود' });
      res.json({ message: 'تم تحديث المصروف بنجاح' });
    }
  );
});

app.delete('/general-expenses/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM general_expenses WHERE id = ?', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف المصروف' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'المصروف غير موجود' });
    res.json({ message: 'تم حذف المصروف نهائياً' });
  });
});

app.listen(PORT, () => {
  console.log(`السيرفر شغال على http://localhost:${PORT}`);
});
