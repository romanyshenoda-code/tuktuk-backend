const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;

app.use(express.json());

// إعداد رفع الصور
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});
const upload = multer({ storage: storage });
app.use('/uploads', express.static('uploads'));

// دالة تجيب قيمة إعداد معين من قاعدة البيانات
function getSetting(key, callback) {
  db.query('SELECT setting_value FROM system_settings WHERE setting_key = ?', [key], (err, results) => {
    if (err || results.length === 0) {
      return callback(null, 'false');
    }
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
  if (req.session && req.session.loggedIn) {
    return next();
  }
  return res.redirect('/login.html');
}

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) {
    req.session.loggedIn = true;
    res.json({ message: 'تم تسجيل الدخول بنجاح' });
  } else {
    res.status(401).json({ error: 'الباسورد غلط' });
  }
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// ==================== تسجيل دخول السائق ====================
function requireDriverLogin(req, res, next) {
  if (req.session && req.session.driverId) {
    return next();
  }
  return res.redirect('/driver-login.html');
}

app.post('/api/driver-login', (req, res) => {
  const { driver_id, password } = req.body;

  db.query('SELECT * FROM drivers WHERE id = ? AND password = ?', [driver_id, password], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تسجيل الدخول' });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: 'رقم السائق أو الباسورد غلط' });
    }

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

// ==================== الصفحات الرئيسية ====================
app.get('/', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.use(express.static('public'));

// ==================== الإعدادات ====================
app.get('/settings', (req, res) => {
  db.query('SELECT setting_key, setting_value FROM system_settings', (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الإعدادات' });
    }
    res.json(results);
  });
});

app.put('/settings/:key', (req, res) => {
  const { key } = req.params;
  const { value } = req.body;

  db.query('UPDATE system_settings SET setting_value = ? WHERE setting_key = ?', [value, key], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تحديث الإعداد' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'الإعداد غير موجود' });
    }
    res.json({ message: 'تم تحديث الإعداد بنجاح' });
  });
});

// ==================== السواقين ====================
app.post('/drivers', (req, res) => {
  const { name, phone, national_id, password } = req.body;

  const query = 'INSERT INTO drivers (name, phone, national_id, password) VALUES (?, ?, ?, ?)';
  db.query(query, [name, phone, national_id, password], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في حفظ السائق' });
    }
    res.status(201).json({ message: 'تم تسجيل السائق بنجاح', driver_id: result.insertId });
  });
});

app.get('/drivers', (req, res) => {
  const query = 'SELECT * FROM drivers';
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب السواقين' });
    }
    res.json(results);
  });
});

// ==================== التوكتوكات ====================
app.post('/tuktuks', (req, res) => {
  const { tuktuk_number, qr_code } = req.body;

  const query = 'INSERT INTO tuktuks (tuktuk_number, qr_code) VALUES (?, ?)';
  db.query(query, [tuktuk_number, qr_code], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تسجيل التوكتوك' });
    }
    res.status(201).json({ message: 'تم تسجيل التوكتوك بنجاح', tuktuk_id: result.insertId });
  });
});

app.get('/tuktuks', (req, res) => {
  const query = 'SELECT * FROM tuktuks';
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب التوكتوكات' });
    }
    res.json(results);
  });
});

// ==================== مواقع الحضور ====================
app.post('/admin-locations', (req, res) => {
  const { name, latitude, longitude, radius_meters } = req.body;

  const query = 'INSERT INTO admin_locations (name, latitude, longitude, radius_meters) VALUES (?, ?, ?, ?)';
  db.query(query, [name, latitude, longitude, radius_meters || 100], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تسجيل الموقع' });
    }
    res.status(201).json({ message: 'تم تسجيل الموقع بنجاح', location_id: result.insertId });
  });
});

// ==================== الحضور (Check-in) ====================
app.post('/shifts/check-in', upload.single('photo'), (req, res) => {
  const { driver_id, tuktuk_qr_code, lat, lng } = req.body;
  const photo = req.file ? req.file.filename : null;

  getSetting('photo_required_checkin', (err, required) => {
    if (required === 'true' && !photo) {
      return res.status(400).json({ error: 'الصورة إجبارية عند تسجيل الحضور' });
    }

    const findTuktuk = 'SELECT id FROM tuktuks WHERE qr_code = ?';
    db.query(findTuktuk, [tuktuk_qr_code], (err, tuktukResults) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في البحث عن التوكتوك' });
      }
      if (tuktukResults.length === 0) {
        return res.status(404).json({ error: 'كود QR غير معروف' });
      }

      const tuktuk_id = tuktukResults[0].id;

      const insertShift = `
        INSERT INTO shifts (driver_id, tuktuk_id, check_in_time, check_in_photo, check_in_lat, check_in_lng, status)
        VALUES (?, ?, NOW(), ?, ?, ?, 'open')
      `;
      db.query(insertShift, [driver_id, tuktuk_id, photo, lat, lng], (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'حصل خطأ في تسجيل الحضور' });
        }
        res.status(201).json({ message: 'تم تسجيل الحضور بنجاح', shift_id: result.insertId, tuktuk_id });
      });
    });
  });
});

// ==================== الانصراف (Check-out) ====================
app.post('/shifts/check-out', upload.single('photo'), (req, res) => {
  const { shift_id } = req.body;
  const photo = req.file ? req.file.filename : null;

  getSetting('photo_required_checkout', (err, required) => {
    if (required === 'true' && !photo) {
      return res.status(400).json({ error: 'الصورة إجبارية عند تسجيل الانصراف' });
    }

    const updateShift = `
      UPDATE shifts
      SET check_out_time = NOW(), check_out_photo = ?, status = 'closed'
      WHERE id = ? AND status = 'open'
    `;
    db.query(updateShift, [photo, shift_id], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في تسجيل الانصراف' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'الوردية غير موجودة أو مقفولة بالفعل' });
      }
      res.json({ message: 'تم تسجيل الانصراف بنجاح' });
    });
  });
});

// ==================== فتح أوردر ====================
app.post('/orders/open', (req, res) => {
  const { shift_id, driver_id, order_type, start_lat, start_lng } = req.body;

  const checkOpen = 'SELECT id FROM orders WHERE driver_id = ? AND status = "open"';
  db.query(checkOpen, [driver_id], (err, openResults) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في التحقق من الأوردرات' });
    }
    if (openResults.length > 0) {
      return res.status(400).json({ error: 'السائق عنده أوردر مفتوح بالفعل، لازم يقفله الأول' });
    }

    const getPricing = 'SELECT driver_commission_pct FROM pricing_rules WHERE order_type = ? ORDER BY effective_from DESC LIMIT 1';
    db.query(getPricing, [order_type], (err, pricingResults) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في جلب التسعيرة' });
      }
      if (pricingResults.length === 0) {
        return res.status(400).json({ error: 'مفيش تسعيرة محددة لنوع الرحلة ده' });
      }

      const commission_pct = pricingResults[0].driver_commission_pct;

      const insertOrder = `
        INSERT INTO orders (shift_id, driver_id, order_type, start_lat, start_lng, start_time, driver_commission_pct, status)
        VALUES (?, ?, ?, ?, ?, NOW(), ?, 'open')
      `;
      db.query(insertOrder, [shift_id, driver_id, order_type, start_lat, start_lng, commission_pct], (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'حصل خطأ في فتح الأوردر' });
        }
        res.status(201).json({ message: 'تم فتح الأوردر بنجاح', order_id: result.insertId });
      });
    });
  });
});

// دالة حساب المسافة بمعادلة Haversine
function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// ==================== قفل أوردر (مع صورة اختيارية) ====================
app.post('/orders/close', upload.single('photo'), (req, res) => {
  const { order_id, end_lat, end_lng } = req.body;
  const photo = req.file ? req.file.filename : null;

  getSetting('photo_required_order_close', (err, required) => {
    if (required === 'true' && !photo) {
      return res.status(400).json({ error: 'الصورة إجبارية عند قفل الأوردر' });
    }

    const getOrder = 'SELECT * FROM orders WHERE id = ? AND status = "open"';
    db.query(getOrder, [order_id], (err, orderResults) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في جلب الأوردر' });
      }
      if (orderResults.length === 0) {
        return res.status(404).json({ error: 'الأوردر غير موجود أو مقفول بالفعل' });
      }

      const order = orderResults[0];
      const distance_km = calculateDistance(order.start_lat, order.start_lng, end_lat, end_lng);

      const getPricing = 'SELECT * FROM pricing_rules WHERE order_type = ? ORDER BY effective_from DESC LIMIT 1';
      db.query(getPricing, [order.order_type], (err, pricingResults) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'حصل خطأ في جلب التسعيرة' });
        }

        const pricing = pricingResults[0];
        let price = 0;

        if (order.order_type === 'delivery') {
          price = distance_km * pricing.price_per_km;
        } else if (order.order_type === 'full_trip') {
          price = pricing.price_per_day;
        }

        const driver_earning = price * (order.driver_commission_pct / 100);

        const updateOrder = `
          UPDATE orders
          SET end_lat = ?, end_lng = ?, end_time = NOW(), distance_km = ?, price = ?, driver_earning = ?, status = 'closed', delivery_photo = ?
          WHERE id = ?
        `;
        db.query(updateOrder, [end_lat, end_lng, distance_km.toFixed(2), price.toFixed(2), driver_earning.toFixed(2), photo, order_id], (err, result) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: 'حصل خطأ في قفل الأوردر' });
          }
          res.json({
            message: 'تم قفل الأوردر بنجاح',
            distance_km: distance_km.toFixed(2),
            price: price.toFixed(2),
            driver_earning: driver_earning.toFixed(2)
          });
        });
      });
    });
  });
});

// ==================== ملخص الوردية ====================
app.post('/shifts/:shift_id/summary', (req, res) => {
  const { shift_id } = req.params;

  const getOrders = 'SELECT * FROM orders WHERE shift_id = ? AND status = "closed"';
  db.query(getOrders, [shift_id], (err, orders) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب أوردرات الوردية' });
    }

    const total_orders = orders.length;
    const full_trip_count = orders.filter(o => o.order_type === 'full_trip').length;
    const delivery_count = orders.filter(o => o.order_type === 'delivery').length;
    const total_price = orders.reduce((sum, o) => sum + parseFloat(o.price || 0), 0);
    const total_driver_earning = orders.reduce((sum, o) => sum + parseFloat(o.driver_earning || 0), 0);

    const insertSummary = `
      INSERT INTO shift_summary (shift_id, total_orders, full_trip_count, delivery_count, total_price, total_driver_earning)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(insertSummary, [shift_id, total_orders, full_trip_count, delivery_count, total_price.toFixed(2), total_driver_earning.toFixed(2)], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في حفظ الملخص' });
      }
      res.status(201).json({
        message: 'تم إنشاء ملخص الوردية بنجاح',
        summary_id: result.insertId,
        total_orders,
        full_trip_count,
        delivery_count,
        total_price: total_price.toFixed(2),
        total_driver_earning: total_driver_earning.toFixed(2)
      });
    });
  });
});

app.put('/shift-summary/:id', (req, res) => {
  const { id } = req.params;
  const { field_name, new_value, admin_id } = req.body;

  const allowedFields = ['total_orders', 'full_trip_count', 'delivery_count', 'total_price', 'total_driver_earning'];
  if (!allowedFields.includes(field_name)) {
    return res.status(400).json({ error: 'الحقل ده مش مسموح تعديله' });
  }

  const getOld = `SELECT ${field_name} AS old_value FROM shift_summary WHERE id = ?`;
  db.query(getOld, [id], (err, oldResults) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب البيانات' });
    }
    if (oldResults.length === 0) {
      return res.status(404).json({ error: 'الملخص غير موجود' });
    }

    const old_value = oldResults[0].old_value;

    const updateQuery = `UPDATE shift_summary SET ${field_name} = ?, is_manually_edited = TRUE, edited_by = ?, edited_at = NOW() WHERE id = ?`;
    db.query(updateQuery, [new_value, admin_id, id], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في التعديل' });
      }

      const logQuery = `
        INSERT INTO audit_logs (entity_type, entity_id, admin_id, field_name, old_value, new_value)
        VALUES ('shift_summary', ?, ?, ?, ?, ?)
      `;
      db.query(logQuery, [id, admin_id, field_name, old_value, new_value], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'حصل خطأ في تسجيل السجل' });
        }
        res.json({ message: 'تم التعديل وتسجيله بنجاح', field_name, old_value, new_value });
      });
    });
  });
});

// ==================== جلب البيانات ====================
app.get('/shifts', (req, res) => {
  const query = `
    SELECT shifts.*, drivers.name AS driver_name, tuktuks.tuktuk_number
    FROM shifts
    JOIN drivers ON shifts.driver_id = drivers.id
    JOIN tuktuks ON shifts.tuktuk_id = tuktuks.id
    ORDER BY shifts.check_in_time DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الورديات' });
    }
    res.json(results);
  });
});

app.get('/orders', (req, res) => {
  const query = `
    SELECT orders.*, drivers.name AS driver_name
    FROM orders
    JOIN drivers ON orders.driver_id = drivers.id
    ORDER BY orders.start_time DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الأوردرات' });
    }
    res.json(results);
  });
});

app.get('/shift-summaries', (req, res) => {
  const query = `
    SELECT shift_summary.*, drivers.name AS driver_name
    FROM shift_summary
    JOIN shifts ON shift_summary.shift_id = shifts.id
    JOIN drivers ON shifts.driver_id = drivers.id
    ORDER BY shift_summary.created_at DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الملخصات' });
    }
    res.json(results);
  });
});

app.get('/shifts/open/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  const query = 'SELECT * FROM shifts WHERE driver_id = ? AND status = "open"';
  db.query(query, [driver_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في البحث عن الوردية' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'مفيش وردية مفتوحة للسائق ده' });
    }
    res.json(results[0]);
  });
});

// ==================== طلبات الإجازة ====================
app.post('/leave-requests', (req, res) => {
  const { driver_id, start_date, end_date, reason } = req.body;

  const query = 'INSERT INTO leave_requests (driver_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)';
  db.query(query, [driver_id, start_date, end_date, reason], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تسجيل طلب الإجازة' });
    }
    res.status(201).json({ message: 'تم إرسال طلب الإجازة بنجاح', request_id: result.insertId });
  });
});

app.get('/leave-requests', (req, res) => {
  const query = `
    SELECT leave_requests.*, drivers.name AS driver_name
    FROM leave_requests
    JOIN drivers ON leave_requests.driver_id = drivers.id
    ORDER BY leave_requests.created_at DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب طلبات الإجازة' });
    }
    res.json(results);
  });
});

app.get('/leave-requests/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM leave_requests WHERE driver_id = ? ORDER BY created_at DESC', [driver_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب طلبات الإجازة' });
    }
    res.json(results);
  });
});

app.put('/leave-requests/:id', (req, res) => {
  const { id } = req.params;
  const { status, admin_note } = req.body;

  db.query('SELECT * FROM leave_requests WHERE id = ?', [id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الطلب' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'الطلب غير موجود' });
    }

    const request = results[0];

    db.query('UPDATE leave_requests SET status = ?, admin_note = ?, reviewed_at = NOW() WHERE id = ?', [status, admin_note, id], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في تحديث الطلب' });
      }

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

  const query = 'INSERT INTO advances (driver_id, amount, reason) VALUES (?, ?, ?)';
  db.query(query, [driver_id, amount, reason], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تسجيل طلب السلفة' });
    }
    res.status(201).json({ message: 'تم إرسال طلب السلفة بنجاح', request_id: result.insertId });
  });
});

app.get('/advances', (req, res) => {
  const query = `
    SELECT advances.*, drivers.name AS driver_name
    FROM advances
    JOIN drivers ON advances.driver_id = drivers.id
    ORDER BY advances.created_at DESC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب طلبات السلف' });
    }
    res.json(results);
  });
});

app.get('/advances/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM advances WHERE driver_id = ? ORDER BY created_at DESC', [driver_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب طلبات السلف' });
    }
    res.json(results);
  });
});

app.put('/advances/:id', (req, res) => {
  const { id } = req.params;
  const { status, admin_note } = req.body;

  db.query('SELECT * FROM advances WHERE id = ?', [id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الطلب' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'الطلب غير موجود' });
    }

    const request = results[0];

    db.query('UPDATE advances SET status = ?, admin_note = ?, reviewed_at = NOW() WHERE id = ?', [status, admin_note, id], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'حصل خطأ في تحديث الطلب' });
      }

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

  const query = 'INSERT INTO deductions (driver_id, amount, reason) VALUES (?, ?, ?)';
  db.query(query, [driver_id, amount, reason], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تسجيل الخصم' });
    }

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
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الخصومات' });
    }
    res.json(results);
  });
});

// ==================== الإشعارات ====================
app.get('/notifications/driver/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  db.query('SELECT * FROM notifications WHERE driver_id = ? ORDER BY created_at DESC LIMIT 20', [driver_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب الإشعارات' });
    }
    res.json(results);
  });
});

app.put('/notifications/:id/read', (req, res) => {
  const { id } = req.params;
  db.query('UPDATE notifications SET is_read = TRUE WHERE id = ?', [id], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في تحديث الإشعار' });
    }
    res.json({ message: 'تم' });
  });
});
// سجل ورديات سائق معين
app.get('/shifts/history/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  const query = `
    SELECT shifts.*, tuktuks.tuktuk_number
    FROM shifts
    JOIN tuktuks ON shifts.tuktuk_id = tuktuks.id
    WHERE shifts.driver_id = ?
    ORDER BY shifts.check_in_time DESC
    LIMIT 10
  `;
  db.query(query, [driver_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب سجل الورديات' });
    }
    res.json(results);
  });
});

// سجل أوردرات سائق معين
app.get('/orders/history/:driver_id', (req, res) => {
  const { driver_id } = req.params;
  const query = `
    SELECT * FROM orders
    WHERE driver_id = ? AND status = 'closed'
    ORDER BY start_time DESC
    LIMIT 20
  `;
  db.query(query, [driver_id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في جلب سجل الأوردرات' });
    }
    res.json(results);
  });
});
app.listen(PORT, () => {
  console.log(`السيرفر شغال على http://localhost:${PORT}`);
});
