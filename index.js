const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const compression = require('compression');
const db = require('./db');

const app = express();
const PORT = 3000;

app.use(compression());
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

// ==================== تسجيل دخول الأدمن (مشفّر) ====================
function requireLogin(req, res, next) {
  if (!req.session || !req.session.loggedIn) return res.redirect('/login.html');

  db.query('SELECT id FROM admins WHERE id = ?', [req.session.adminId], (err, results) => {
    if (err || results.length === 0) {
      req.session.destroy(() => {});
      return res.redirect('/login.html');
    }
    next();
  });
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM admins WHERE username = ?', [username], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' }); }
    if (results.length === 0) return res.status(401).json({ error: 'اسم المستخدم أو الباسورد غلط' });

    const admin = results[0];
    const isMatch = bcrypt.compareSync(password, admin.password || '');
    if (!isMatch) return res.status(401).json({ error: 'اسم المستخدم أو الباسورد غلط' });

    req.session.loggedIn = true;
    req.session.adminId = admin.id;
    req.session.adminName = admin.name;
    res.json({ message: 'تم تسجيل الدخول بنجاح' });
  });
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// ==================== إدارة الأدمنية (مع تشفير) ====================
app.get('/admins', (req, res) => {
  db.query('SELECT id, name, username, created_at FROM admins', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأدمنية' }); }
    res.json(results);
  });
});

app.post('/admins', (req, res) => {
  const { name, username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.query('INSERT INTO admins (name, username, password) VALUES (?, ?, ?)', [name, username, hashed], (err, result) => {
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
  if (!password) return res.status(400).json({ error: 'من فضلك ابعت الباسورد الجديد' });
  const hashed = bcrypt.hashSync(password, 10);
  db.query('UPDATE admins SET password = ? WHERE id = ?', [hashed, id], (err) => {
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

// ==================== تسجيل دخول السائق (مشفّر) ====================
app.post('/api/driver-login', (req, res) => {
  const { driver_id, password } = req.body;
  db.query('SELECT * FROM drivers WHERE id = ?', [driver_id], (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' }); }
    if (results.length === 0) return res.status(401).json({ error: 'رقم السائق أو الباسورد غلط' });

    const driver = results[0];
    const isMatch = bcrypt.compareSync(password, driver.password || '');
    if (!isMatch) return res.status(401).json({ error: 'رقم السائق أو الباسورد غلط' });

    req.session.driverId = driver.id;
    req.session.driverName = driver.name;
    res.json({ message: 'تم تسجيل الدخول بنجاح', driver });
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

// ==================== تسجيل دخول قسم المالية (مشفّر) ====================
function requireFinanceLogin(req, res, next) {
  if (req.session && req.session.financeLoggedIn) return next();
  return res.redirect('/finance-login.html');
}

app.post('/api/finance-login', (req, res) => {
  const { password } = req.body;
  db.query('SELECT * FROM finance_admin', (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' }); }
    if (results.length === 0) return res.status(401).json({ error: 'مفيش حساب مالية مسجل' });

    const isMatch = results.some(f => bcrypt.compareSync(password, f.password || ''));
    if (!isMatch) return res.status(401).json({ error: 'الباسورد غلط' });

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

app.get('/api/admin-session', (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.loggedIn) });
});

// ==================== الصفحات المحمية ====================
const adminProtectedPages = [
  '/', '/index', '/index.html',
  '/drivers', '/drivers.html',
  '/tuktuks', '/tuktuks.html',
  '/shifts', '/shifts.html',
  '/orders', '/orders.html',
  '/hr', '/hr.html',
  '/admins', '/admins.html',
  '/manual-orders', '/manual-orders.html'
];

const driverProtectedPages = [
  '/driver', '/driver.html',
  '/driver-attendance', '/driver-attendance.html',
  '/driver-orders', '/driver-orders.html',
  '/driver-requests', '/driver-requests.html'
];

app.use((req, res, next) => {
  const reqPath = req.path;
  const isAdminPage = adminProtectedPages.includes(reqPath);
  const isDriverPage = driverProtectedPages.includes(reqPath);
  const isFinancePage = (reqPath === '/finance' || reqPath === '/finance.html');

  if (isAdminPage || isDriverPage || isFinancePage) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }

  if (isAdminPage) {
    if (req.session && req.session.loggedIn) return next();
    return res.redirect('/login.html');
  }

  if (isDriverPage) {
    if (req.session && req.session.driverId) return next();
    return res.redirect('/driver-login.html');
  }

  if (isFinancePage) {
    if (req.session && req.session.financeLoggedIn) return next();
    return res.redirect('/finance-login.html');
  }

  next();
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

// ==================== السواقين (مع تشفير) ====================
app.post('/drivers', (req, res) => {
  const { name, phone, national_id, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.query('INSERT INTO drivers (name, phone, national_id, password) VALUES (?, ?, ?, ?)', [name, phone, national_id, hashed], (err, result) => {
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
  const hashed = bcrypt.hashSync(password, 10);
  db.query('UPDATE drivers SET password = ? WHERE id = ?', [hashed, id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في تحديث الباسورد' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'السائق غير موجود' });
    res.json({ message: 'تم تغيير الباسورد بنجاح' });
  });
});

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

    // نجيب نسبة العمولة من إعدادات الدخل (مصدر واحد للأسعار)
    db.query('SELECT * FROM payroll_settings ORDER BY id DESC LIMIT 1', (err, settingsResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
      const settings = settingsResults[0];
      if (!settings) return res.status(400).json({ error: 'مفيش إعدادات أسعار، اضبطها من قسم المالية الأول' });

      let commission_pct = 0;
      if (order_type === 'delivery') commission_pct = parseFloat(settings.delivery_commission_pct || 0);
      else if (order_type === 'full_trip') commission_pct = parseFloat(settings.full_trip_commission_pct || 0);

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

      db.query('SELECT * FROM payroll_settings ORDER BY id DESC LIMIT 1', (err, settingsResults) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
        const settings = settingsResults[0];
        if (!settings) return res.status(400).json({ error: 'مفيش إعدادات أسعار، اضبطها من قسم المالية' });

        // سعر ثابت حسب نوع الأوردر (مفيش حساب بالكيلومتر)
        let price = 0;
        if (order.order_type === 'delivery') price = parseFloat(settings.delivery_base_price || 0);
        else if (order.order_type === 'full_trip') price = parseFloat(settings.full_trip_base_price || 0);

        // نسبة العمولة حسب نوع الأوردر
        let commissionPct = 0;
        if (order.order_type === 'delivery') commissionPct = parseFloat(settings.delivery_commission_pct || 0);
        else if (order.order_type === 'full_trip') commissionPct = parseFloat(settings.full_trip_commission_pct || 0);

        const driver_earning = price * (commissionPct / 100);

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
  const rowLimit = parseInt(req.query.limit) || 300;
  db.query(
    `SELECT shifts.*, drivers.name AS driver_name, tuktuks.tuktuk_number FROM shifts JOIN drivers ON shifts.driver_id = drivers.id JOIN tuktuks ON shifts.tuktuk_id = tuktuks.id ORDER BY shifts.check_in_time DESC LIMIT ` + rowLimit,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الورديات' }); }
      res.json(results);
    }
  );
});

app.get('/orders', (req, res) => {
  const rowLimit = parseInt(req.query.limit) || 300;
  db.query(
    `SELECT orders.*, drivers.name AS driver_name FROM orders JOIN drivers ON orders.driver_id = drivers.id ORDER BY orders.start_time DESC LIMIT ` + rowLimit,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأوردرات' }); }
      res.json(results);
    }
  );
});

app.get('/shift-summaries', (req, res) => {
  db.query(
    `SELECT shift_summary.*, drivers.name AS driver_name FROM shift_summary JOIN shifts ON shift_summary.shift_id = shifts.id JOIN drivers ON shifts.driver_id = drivers.id ORDER BY shift_summary.created_at DESC LIMIT 300`,
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

app.delete('/leave-requests/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM leave_requests WHERE id = ?', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف طلب الإجازة' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الطلب غير موجود' });
    res.json({ message: 'تم حذف طلب الإجازة نهائياً' });
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

app.delete('/advances/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM advances WHERE id = ?', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف طلب السلفة' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الطلب غير موجود' });
    res.json({ message: 'تم حذف طلب السلفة نهائياً' });
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

// ==================== إعدادات الرواتب العامة ====================
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
    (err) => {
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

// ==================== حساب راتب سائق لشهر معين ====================
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
  const { year, month } = req.query;
  let query = `SELECT tuktuk_maintenance.*, tuktuks.tuktuk_number, drivers.name AS driver_name FROM tuktuk_maintenance JOIN tuktuks ON tuktuk_maintenance.tuktuk_id = tuktuks.id LEFT JOIN drivers ON tuktuk_maintenance.driver_id = drivers.id`;
  const params = [];
  if (year && month) {
    query += ' WHERE YEAR(tuktuk_maintenance.maintenance_date) = ? AND MONTH(tuktuk_maintenance.maintenance_date) = ?';
    params.push(year, month);
  }
  query += ' ORDER BY tuktuk_maintenance.maintenance_date DESC LIMIT 500';

  db.query(query, params, (err, results) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب سجل الصيانة' }); }
    res.json(results);
  });
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
  const { year, month } = req.query;
  let query = 'SELECT * FROM general_expenses';
  const params = [];
  if (year && month) {
    query += ' WHERE YEAR(expense_date) = ? AND MONTH(expense_date) = ?';
    params.push(year, month);
  }
  query += ' ORDER BY expense_date DESC LIMIT 500';

  db.query(query, params, (err, results) => {
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

// ==================== تقرير أداء السواقين ====================
app.get('/reports/driver-performance/:year/:month', (req, res) => {
  const { year, month } = req.params;

  db.query(
    `SELECT driver_id, COUNT(DISTINCT DATE(check_in_time)) AS days_worked
     FROM shifts WHERE YEAR(check_in_time) = ? AND MONTH(check_in_time) = ?
     GROUP BY driver_id`,
    [year, month],
    (err, shiftsRows) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب أيام العمل' }); }

      db.query(
        `SELECT driver_id, order_type, COUNT(*) AS cnt, COALESCE(SUM(price), 0) AS revenue
         FROM orders WHERE status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ?
         GROUP BY driver_id, order_type`,
        [year, month],
        (err, ordersRows) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الأوردرات' }); }

          db.query('SELECT id, name FROM drivers', (err, drivers) => {
            if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب السواقين' }); }

            const daysMap = {};
            shiftsRows.forEach(r => { daysMap[r.driver_id] = r.days_worked; });

            const ordersMap = {};
            ordersRows.forEach(r => {
              if (!ordersMap[r.driver_id]) ordersMap[r.driver_id] = { delivery: 0, full_trip: 0, revenue: 0 };
              ordersMap[r.driver_id][r.order_type] = r.cnt;
              ordersMap[r.driver_id].revenue += parseFloat(r.revenue);
            });

            const results = drivers.map(d => {
              const o = ordersMap[d.id] || { delivery: 0, full_trip: 0, revenue: 0 };
              return {
                driver_id: d.id,
                driver_name: d.name,
                days_worked: daysMap[d.id] || 0,
                total_orders: (o.delivery || 0) + (o.full_trip || 0),
                delivery_count: o.delivery || 0,
                full_trip_count: o.full_trip || 0,
                total_revenue: o.revenue.toFixed(2)
              };
            });

            results.sort((a, b) => parseFloat(b.total_revenue) - parseFloat(a.total_revenue));
            res.json(results);
          });
        }
      );
    }
  );
});

// ==================== بيانات الرسم البياني السنوي ====================
app.get('/reports/yearly-chart/:year', (req, res) => {
  const { year } = req.params;

  db.query(
    `SELECT MONTH(start_time) AS month, COALESCE(SUM(price), 0) AS revenue
     FROM orders WHERE status = 'closed' AND YEAR(start_time) = ?
     GROUP BY MONTH(start_time)`,
    [year],
    (err, revenueResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإيرادات' }); }

      db.query(
        `SELECT MONTH(maintenance_date) AS month, COALESCE(SUM(cost), 0) AS total
         FROM tuktuk_maintenance WHERE YEAR(maintenance_date) = ?
         GROUP BY MONTH(maintenance_date)`,
        [year],
        (err, maintResults) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الصيانة' }); }

          db.query(
            `SELECT MONTH(expense_date) AS month, COALESCE(SUM(amount), 0) AS total
             FROM general_expenses WHERE YEAR(expense_date) = ?
             GROUP BY MONTH(expense_date)`,
            [year],
            (err, genResults) => {
              if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب المصروفات' }); }

              const months = Array.from({ length: 12 }, (_, i) => i + 1);
              const data = months.map(m => {
                const rev = revenueResults.find(r => r.month === m);
                const maint = maintResults.find(r => r.month === m);
                const gen = genResults.find(r => r.month === m);
                return {
                  month: m,
                  revenue: parseFloat(rev ? rev.revenue : 0),
                  maintenance: parseFloat(maint ? maint.total : 0),
                  general: parseFloat(gen ? gen.total : 0)
                };
              });

              res.json(data);
            }
          );
        }
      );
    }
  );
});

// ==================== إحصائيات وتنبيهات الأدمن ====================
app.get('/dashboard/stats', (req, res) => {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;

  db.query(
    `SELECT d.name, COALESCE(SUM(o.price), 0) AS revenue
     FROM drivers d
     LEFT JOIN orders o ON d.id = o.driver_id AND o.status = 'closed'
       AND YEAR(o.start_time) = ? AND MONTH(o.start_time) = ?
     GROUP BY d.id, d.name ORDER BY revenue DESC LIMIT 1`,
    [year, month],
    (err, topDriver) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في الإحصائيات' }); }

      db.query(
        `SELECT t.tuktuk_number, COUNT(*) AS times
         FROM tuktuk_maintenance m JOIN tuktuks t ON m.tuktuk_id = t.id
         WHERE YEAR(m.maintenance_date) = ? AND MONTH(m.maintenance_date) = ?
         GROUP BY t.id, t.tuktuk_number ORDER BY times DESC LIMIT 1`,
        [year, month],
        (err, topMaint) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في الإحصائيات' }); }

          db.query(
            `SELECT COUNT(*) AS total_orders, COUNT(DISTINCT DATE(start_time)) AS active_days
             FROM orders WHERE status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ?`,
            [year, month],
            (err, avgResult) => {
              if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في الإحصائيات' }); }

              const totalOrders = avgResult[0].total_orders || 0;
              const activeDays = avgResult[0].active_days || 0;
              const avgPerDay = activeDays > 0 ? (totalOrders / activeDays).toFixed(1) : '0';

              res.json({
                top_driver: topDriver.length > 0 && parseFloat(topDriver[0].revenue) > 0
                  ? { name: topDriver[0].name, revenue: parseFloat(topDriver[0].revenue).toFixed(0) } : null,
                top_maintenance: topMaint.length > 0
                  ? { tuktuk_number: topMaint[0].tuktuk_number, times: topMaint[0].times } : null,
                avg_orders_per_day: avgPerDay
              });
            }
          );
        }
      );
    }
  );
});

app.get('/dashboard/alerts', (req, res) => {
  const alerts = [];
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;

  db.query(
    `SELECT d.name, MAX(s.check_in_time) AS last_shift
     FROM drivers d LEFT JOIN shifts s ON d.id = s.driver_id
     GROUP BY d.id, d.name
     HAVING last_shift IS NULL OR last_shift < DATE_SUB(NOW(), INTERVAL 3 DAY)`,
    (err, absentDrivers) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في التنبيهات' }); }

      absentDrivers.forEach(d => {
        if (!d.last_shift) {
          alerts.push({ type: 'warning', message: `${d.name} ماسجّلش أي حضور لحد دلوقتي` });
        } else {
          const days = Math.floor((now - new Date(d.last_shift)) / (1000 * 60 * 60 * 24));
          alerts.push({ type: 'warning', message: `${d.name} ماسجّلش حضور من ${days} يوم` });
        }
      });

      db.query(
        `SELECT t.tuktuk_number, COUNT(*) AS times
         FROM tuktuk_maintenance m JOIN tuktuks t ON m.tuktuk_id = t.id
         WHERE YEAR(m.maintenance_date) = ? AND MONTH(m.maintenance_date) = ?
         GROUP BY t.id, t.tuktuk_number HAVING times >= 3`,
        [year, month],
        (err, repeatMaint) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في التنبيهات' }); }

          repeatMaint.forEach(t => {
            alerts.push({ type: 'danger', message: `توكتوك ${t.tuktuk_number} دخل الصيانة ${t.times} مرات الشهر ده` });
          });

          db.query(
            `SELECT d.name, s.check_in_time FROM shifts s JOIN drivers d ON s.driver_id = d.id
             WHERE s.status = 'open' AND s.check_in_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
            (err, longShifts) => {
              if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في التنبيهات' }); }

              longShifts.forEach(s => {
                alerts.push({ type: 'danger', message: `${s.name} عنده وردية مفتوحة من أكتر من 24 ساعة` });
              });

              res.json(alerts);
            }
          );
        }
      );
    }
  );
});

// ==================== إحصائيات السائق ====================
app.get('/driver/stats/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;

  db.query(
    `SELECT COUNT(*) AS orders_count FROM orders
     WHERE driver_id = ? AND status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ?`,
    [driver_id, year, month],
    (err, ordersResult) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في الإحصائيات' }); }

      db.query(
        `SELECT COALESCE(SUM(driver_earning), 0) AS earnings FROM orders
         WHERE driver_id = ? AND status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ?`,
        [driver_id, year, month],
        (err, earningsResult) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في الإحصائيات' }); }

          res.json({
            orders_count: ordersResult[0].orders_count || 0,
            earnings: parseFloat(earningsResult[0].earnings || 0).toFixed(0)
          });
        }
      );
    }
  );
});

// ==================== حساب مرتبات كل السواقين دفعة واحدة (أسرع بكتير) ====================
app.get('/payroll/calculate-all/:year/:month', (req, res) => {
  const { year, month } = req.params;

  db.query('SELECT * FROM drivers', (err, drivers) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب السواقين' }); }
    if (drivers.length === 0) return res.json([]);

    db.query('SELECT * FROM payroll_settings ORDER BY id DESC LIMIT 1', (err, settingsResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
      const settings = settingsResults[0] || {};

      db.query('SELECT * FROM leave_config ORDER BY id DESC LIMIT 1', (err, leaveResults) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب إعدادات الإجازات' }); }
        const leaveConfig = leaveResults[0] || {};

        // استعلام واحد للحضور لكل السواقين
        db.query(
          `SELECT driver_id, COUNT(DISTINCT DATE(check_in_time)) AS days_present
           FROM shifts WHERE YEAR(check_in_time) = ? AND MONTH(check_in_time) = ?
           GROUP BY driver_id`,
          [year, month],
          (err, attendanceRows) => {
            if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الحضور' }); }

            // استعلام واحد للأوردرات لكل السواقين
            db.query(
              `SELECT driver_id, order_type, COUNT(*) AS cnt, COALESCE(SUM(price),0) AS revenue
               FROM orders WHERE status = 'closed' AND YEAR(start_time) = ? AND MONTH(start_time) = ?
               GROUP BY driver_id, order_type`,
              [year, month],
              (err, orderRows) => {
                if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الأوردرات' }); }

                // استعلام واحد للخصومات
                db.query(
                  `SELECT driver_id, COALESCE(SUM(amount),0) AS total FROM deductions
                   WHERE YEAR(created_at) = ? AND MONTH(created_at) = ? GROUP BY driver_id`,
                  [year, month],
                  (err, deductionRows) => {
                    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الخصومات' }); }

                    // استعلام واحد للسلف
                    db.query(
                      `SELECT driver_id, COALESCE(SUM(amount),0) AS total FROM advances
                       WHERE status = 'approved' AND YEAR(created_at) = ? AND MONTH(created_at) = ? GROUP BY driver_id`,
                      [year, month],
                      (err, advanceRows) => {
                        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب السلف' }); }

                        // استعلام واحد لأيام الأعياد
                        db.query(
                          `SELECT hed.driver_id, he.start_date, he.end_date
                           FROM holiday_events he
                           JOIN holiday_event_drivers hed ON he.id = hed.holiday_event_id
                           WHERE (YEAR(he.start_date) = ? AND MONTH(he.start_date) = ?)
                              OR (YEAR(he.end_date) = ? AND MONTH(he.end_date) = ?)`,
                          [year, month, year, month],
                          (err, holidayRows) => {
                            if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حساب الأعياد' }); }

                            // تجهيز خرائط سريعة
                            const attendanceMap = {};
                            attendanceRows.forEach(r => { attendanceMap[r.driver_id] = r.days_present; });

                            const ordersMap = {};
                            orderRows.forEach(r => {
                              if (!ordersMap[r.driver_id]) ordersMap[r.driver_id] = { delivery: 0, full_trip: 0, revenue: 0 };
                              ordersMap[r.driver_id][r.order_type] = r.cnt;
                              ordersMap[r.driver_id].revenue += parseFloat(r.revenue);
                            });

                            const deductionMap = {};
                            deductionRows.forEach(r => { deductionMap[r.driver_id] = parseFloat(r.total); });

                            const advanceMap = {};
                            advanceRows.forEach(r => { advanceMap[r.driver_id] = parseFloat(r.total); });

                            const holidayMap = {};
                            holidayRows.forEach(h => {
                              const start = new Date(h.start_date);
                              const end = new Date(h.end_date);
                              const days = Math.floor((end - start) / (1000 * 60 * 60 * 24)) + 1;
                              holidayMap[h.driver_id] = (holidayMap[h.driver_id] || 0) + days;
                            });

                            // حساب كل سائق
                            const results = drivers.map(driver => {
                              const income_type = driver.is_customized ? driver.custom_income_type : settings.income_type;
                              const monthly_salary = driver.is_customized ? driver.custom_monthly_salary : settings.monthly_salary;
                              const delivery_commission_pct = driver.is_customized ? driver.custom_delivery_commission_pct : settings.delivery_commission_pct;
                              const full_trip_commission_pct = driver.is_customized ? driver.custom_full_trip_commission_pct : settings.full_trip_commission_pct;
                              const delivery_base_price = driver.is_customized ? driver.custom_delivery_base_price : settings.delivery_base_price;
                              const full_trip_base_price = driver.is_customized ? driver.custom_full_trip_base_price : settings.full_trip_base_price;
                              const baseWorkingDays = driver.is_customized ? driver.custom_working_days : leaveConfig.working_days_per_month;

                              const holidayDaysCount = holidayMap[driver.id] || 0;
                              const requiredWorkingDays = Math.max((baseWorkingDays || 26) - holidayDaysCount, 0);
                              const days_present = attendanceMap[driver.id] || 0;

                              const o = ordersMap[driver.id] || { delivery: 0, full_trip: 0, revenue: 0 };
                              const deliveryCount = o.delivery || 0;
                              const fullTripCount = o.full_trip || 0;
                              const total_revenue = o.revenue || 0;

                              const total_deductions = deductionMap[driver.id] || 0;
                              const total_advances = advanceMap[driver.id] || 0;

                              let salaryPart = 0, deliveryCommission = 0, fullTripCommission = 0;

                              if (income_type === 'salary' || income_type === 'both') {
                                const dailyRate = requiredWorkingDays > 0 ? (monthly_salary || 0) / requiredWorkingDays : 0;
                                const cappedPresentDays = Math.min(days_present, requiredWorkingDays);
                                salaryPart = dailyRate * cappedPresentDays;
                              }

                              if (income_type === 'commission' || income_type === 'both') {
                                deliveryCommission = deliveryCount * parseFloat(delivery_base_price || 0) * (parseFloat(delivery_commission_pct || 0) / 100);
                                fullTripCommission = fullTripCount * parseFloat(full_trip_base_price || 0) * (parseFloat(full_trip_commission_pct || 0) / 100);
                              }

                              const commissionPart = deliveryCommission + fullTripCommission;
                              const grossPay = salaryPart + commissionPart;
                              const netPay = grossPay - total_deductions - total_advances;

                              return {
                                driver_id: driver.id,
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
                              };
                            });

                            res.json(results);
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


// ==================== إضافة أوردر يدوي (من الأدمن) ====================
app.post('/orders/manual', (req, res) => {
  const { driver_id, order_date, order_type, count } = req.body;

  if (!driver_id || !order_date || !order_type) {
    return res.status(400).json({ error: 'كل الحقول مطلوبة' });
  }

  const orderCount = parseInt(count) || 1;
  if (orderCount < 1 || orderCount > 50) {
    return res.status(400).json({ error: 'عدد الأوردرات يجب أن يكون بين 1 و50' });
  }

  db.query('SELECT * FROM drivers WHERE id = ?', [driver_id], (err, driverResults) => {
    if (err || driverResults.length === 0) return res.status(404).json({ error: 'السائق غير موجود' });
    const driver = driverResults[0];

    db.query('SELECT * FROM payroll_settings ORDER BY id DESC LIMIT 1', (err, settingsResults) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' }); }
      const settings = settingsResults[0];

      const delivery_base_price = driver.is_customized ? driver.custom_delivery_base_price : settings.delivery_base_price;
      const full_trip_base_price = driver.is_customized ? driver.custom_full_trip_base_price : settings.full_trip_base_price;
      const delivery_commission_pct = driver.is_customized ? driver.custom_delivery_commission_pct : settings.delivery_commission_pct;
      const full_trip_commission_pct = driver.is_customized ? driver.custom_full_trip_commission_pct : settings.full_trip_commission_pct;

      const price = order_type === 'delivery' ? parseFloat(delivery_base_price || 0) : parseFloat(full_trip_base_price || 0);
      const commissionPct = order_type === 'delivery' ? parseFloat(delivery_commission_pct || 0) : parseFloat(full_trip_commission_pct || 0);
      const driver_earning = price * (commissionPct / 100);

      const dateTimeStr = order_date + ' 12:00:00';

      const values = [];
      for (let i = 0; i < orderCount; i++) {
        values.push([
          driver_id, order_type, dateTimeStr, dateTimeStr,
          price.toFixed(2), driver_earning.toFixed(2), commissionPct,
          'closed', true, order_date
        ]);
      }

      db.query(
        `INSERT INTO orders (driver_id, order_type, start_time, end_time, price, driver_earning, driver_commission_pct, status, is_manual, manual_order_date) VALUES ?`,
        [values],
        (err, result) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في إضافة الأوردر' }); }
          res.status(201).json({
            message: `تم إضافة ${orderCount} أوردر يدوي بنجاح لـ${driver.name}`,
            count: orderCount,
            total_price: (price * orderCount).toFixed(2),
            total_earning: (driver_earning * orderCount).toFixed(2)
          });
        }
      );
    });
  });
});

app.get('/orders/manual', (req, res) => {
  db.query(
    `SELECT orders.*, drivers.name AS driver_name FROM orders JOIN drivers ON orders.driver_id = drivers.id WHERE is_manual = TRUE ORDER BY manual_order_date DESC, orders.id DESC LIMIT 300`,
    (err, results) => {
      if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الأوردرات اليدوية' }); }
      res.json(results);
    }
  );
});

app.delete('/orders/manual/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM orders WHERE id = ? AND is_manual = TRUE', [id], (err, result) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في حذف الأوردر' }); }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'الأوردر غير موجود أو مش يدوي' });
    res.json({ message: 'تم حذف الأوردر اليدوي بنجاح' });
  });
});

// ==================== إحصائيات اليوم للورديات والأوردرات ====================
app.get('/dashboard/today-status', (req, res) => {
  db.query(`SELECT COUNT(*) AS open_count FROM shifts WHERE status = 'open'`, (err, openShifts) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في جلب البيانات' }); }

    db.query(
      `SELECT COUNT(*) AS closed_today FROM shifts WHERE status = 'closed' AND DATE(check_out_time) = CURDATE()`,
      (err, closedShiftsToday) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في جلب البيانات' }); }

        db.query(`SELECT COUNT(*) AS open_count FROM orders WHERE status = 'open'`, (err, openOrders) => {
          if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في جلب البيانات' }); }

          db.query(
            `SELECT COUNT(*) AS closed_today FROM orders WHERE status = 'closed' AND DATE(end_time) = CURDATE()`,
            (err, closedOrdersToday) => {
              if (err) { console.error(err); return res.status(500).json({ error: 'خطأ في جلب البيانات' }); }

              res.json({
                shifts: { open: openShifts[0].open_count, closed_today: closedShiftsToday[0].closed_today },
                orders: { open: openOrders[0].open_count, closed_today: closedOrdersToday[0].closed_today }
              });
            }
          );
        });
      }
    );
  });
});

// ==================== أدوات الصيانة والتنظيف (محمية) ====================
const fs = require('fs');

function verifyFinancePassword(password, callback) {
  db.query('SELECT * FROM finance_admin', (err, results) => {
    if (err) return callback(err, false);
    if (results.length === 0) return callback(null, false);
    const isMatch = results.some(f => bcrypt.compareSync(password || '', f.password || ''));
    callback(null, isMatch);
  });
}

app.post('/maintenance/clean-old-photos', (req, res) => {
  const { password, confirmText } = req.body;
  if (confirmText !== 'مسح الصور') return res.status(400).json({ error: 'كلمة التأكيد غير صحيحة' });

  verifyFinancePassword(password, (err, valid) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في التحقق' }); }
    if (!valid) return res.status(401).json({ error: 'باسورد المالية غلط' });

    const now = new Date();
    const cutoff = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const cutoffStr = cutoff.toISOString().split('T')[0];

    db.query(
      `SELECT check_in_photo AS photo FROM shifts WHERE check_in_time < ? AND check_in_photo IS NOT NULL
       UNION ALL
       SELECT check_out_photo AS photo FROM shifts WHERE check_in_time < ? AND check_out_photo IS NOT NULL
       UNION ALL
       SELECT delivery_photo AS photo FROM orders WHERE start_time < ? AND delivery_photo IS NOT NULL`,
      [cutoffStr, cutoffStr, cutoffStr],
      (err, rows) => {
        if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في جلب الصور' }); }

        let deleted = 0;
        rows.forEach(r => {
          if (!r.photo) return;
          const filePath = path.join(__dirname, 'uploads', r.photo);
          try { if (fs.existsSync(filePath)) { fs.unlinkSync(filePath); deleted++; } } catch (e) {}
        });

        db.query(`UPDATE shifts SET check_in_photo = NULL, check_out_photo = NULL WHERE check_in_time < ?`, [cutoffStr], (err) => {
          if (err) console.error(err);
          db.query(`UPDATE orders SET delivery_photo = NULL WHERE start_time < ?`, [cutoffStr], (err) => {
            if (err) console.error(err);
            res.json({ message: `تم حذف ${deleted} صورة قديمة بنجاح`, deleted, cutoff_date: cutoffStr });
          });
        });
      }
    );
  });
});

app.post('/maintenance/reset-operations', (req, res) => {
  const { password, confirmText } = req.body;
  if (confirmText !== 'مسح البيانات') return res.status(400).json({ error: 'كلمة التأكيد غير صحيحة' });

  verifyFinancePassword(password, (err, valid) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في التحقق' }); }
    if (!valid) return res.status(401).json({ error: 'باسورد المالية غلط' });

    try {
      const uploadsDir = path.join(__dirname, 'uploads');
      if (fs.existsSync(uploadsDir)) {
        fs.readdirSync(uploadsDir).forEach(f => {
          if (f !== '.gitkeep') { try { fs.unlinkSync(path.join(uploadsDir, f)); } catch (e) {} }
        });
      }
    } catch (e) { console.error(e); }

    const queries = [
      'DELETE FROM shift_summary', 'DELETE FROM audit_logs', 'DELETE FROM orders', 'DELETE FROM shifts',
      'DELETE FROM notifications', 'DELETE FROM leave_requests', 'DELETE FROM advances', 'DELETE FROM deductions',
      'DELETE FROM holiday_event_drivers', 'DELETE FROM holiday_events', 'DELETE FROM tuktuk_maintenance', 'DELETE FROM general_expenses'
    ];
    let i = 0;
    function runNext() {
      if (i >= queries.length) return res.json({ message: 'تم مسح كل البيانات التشغيلية بنجاح. السواقين والتوكتوكات لسه موجودين.' });
      db.query(queries[i], (err) => { if (err) console.error('خطأ في: ' + queries[i], err); i++; runNext(); });
    }
    runNext();
  });
});

app.post('/maintenance/factory-reset', (req, res) => {
  const { password, confirmText } = req.body;
  if (confirmText !== 'اعادة تعيين كاملة') return res.status(400).json({ error: 'كلمة التأكيد غير صحيحة' });

  verifyFinancePassword(password, (err, valid) => {
    if (err) { console.error(err); return res.status(500).json({ error: 'حصل خطأ في التحقق' }); }
    if (!valid) return res.status(401).json({ error: 'باسورد المالية غلط' });

    try {
      const uploadsDir = path.join(__dirname, 'uploads');
      if (fs.existsSync(uploadsDir)) {
        fs.readdirSync(uploadsDir).forEach(f => {
          if (f !== '.gitkeep') { try { fs.unlinkSync(path.join(uploadsDir, f)); } catch (e) {} }
        });
      }
    } catch (e) { console.error(e); }

    const queries = [
      'DELETE FROM shift_summary', 'DELETE FROM audit_logs', 'DELETE FROM orders', 'DELETE FROM shifts',
      'DELETE FROM notifications', 'DELETE FROM leave_requests', 'DELETE FROM advances', 'DELETE FROM deductions',
      'DELETE FROM holiday_event_drivers', 'DELETE FROM holiday_events', 'DELETE FROM tuktuk_maintenance', 'DELETE FROM general_expenses',
      'DELETE FROM drivers', 'DELETE FROM tuktuks',
      'ALTER TABLE drivers AUTO_INCREMENT = 1', 'ALTER TABLE tuktuks AUTO_INCREMENT = 1',
      'ALTER TABLE shifts AUTO_INCREMENT = 1', 'ALTER TABLE orders AUTO_INCREMENT = 1'
    ];
    let i = 0;
    function runNext() {
      if (i >= queries.length) return res.json({ message: 'تم إعادة تعيين النظام بالكامل. النظام رجع جديد تماماً.' });
      db.query(queries[i], (err) => { if (err) console.error('خطأ في: ' + queries[i], err); i++; runNext(); });
    }
    runNext();
  });
});

app.get('/maintenance/storage-info', (req, res) => {
  try {
    const uploadsDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadsDir)) return res.json({ files: 0, size_mb: '0' });

    const files = fs.readdirSync(uploadsDir).filter(f => f !== '.gitkeep');
    let totalSize = 0;
    files.forEach(f => { try { totalSize += fs.statSync(path.join(uploadsDir, f)).size; } catch (e) {} });

    res.json({ files: files.length, size_mb: (totalSize / (1024 * 1024)).toFixed(1) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'حصل خطأ في حساب المساحة' });
  }
});


app.listen(PORT, () => {
  console.log(`السيرفر شغال على http://localhost:${PORT}`);
});