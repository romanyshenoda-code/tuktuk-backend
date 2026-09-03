const express = require('express');
const db = require('./db');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.send('السيرفر شغال تمام!');
});

app.post('/drivers', (req, res) => {
  const { name, phone, national_id } = req.body;

  const query = 'INSERT INTO drivers (name, phone, national_id) VALUES (?, ?, ?)';
  db.query(query, [name, phone, national_id], (err, result) => {
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
app.post('/shifts/check-in', (req, res) => {
  const { driver_id, tuktuk_qr_code, lat, lng, photo } = req.body;

  // أول حاجة: نلاقي رقم التوكتوك من الـ QR code
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

    // ندخل الوردية الجديدة
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
app.post('/shifts/check-out', (req, res) => {
  const { shift_id, photo } = req.body;

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
app.post('/orders/open', (req, res) => {
  const { shift_id, driver_id, order_type, start_lat, start_lng } = req.body;

  // أول حاجة: نتأكد إن السائق مفيش أوردر مفتوح بالفعل
  const checkOpen = 'SELECT id FROM orders WHERE driver_id = ? AND status = "open"';
  db.query(checkOpen, [driver_id], (err, openResults) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'حصل خطأ في التحقق من الأوردرات' });
    }
    if (openResults.length > 0) {
      return res.status(400).json({ error: 'السائق عنده أوردر مفتوح بالفعل، لازم يقفله الأول' });
    }

    // نجيب آخر تسعيرة سارية لنوع الرحلة ده
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

      // نفتح الأوردر
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
  const R = 6371; // نصف قطر الأرض بالكيلومتر
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // المسافة بالكيلومتر
}

app.post('/orders/close', (req, res) => {
  const { order_id, end_lat, end_lng } = req.body;

  // نجيب بيانات الأوردر الأول
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

    // نحسب المسافة
    const distance_km = calculateDistance(order.start_lat, order.start_lng, end_lat, end_lng);

    // نجيب التسعيرة الحالية لنوع الرحلة ده
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

      // نقفل الأوردر ونسجل كل الحسابات
      const updateOrder = `
        UPDATE orders
        SET end_lat = ?, end_lng = ?, end_time = NOW(), distance_km = ?, price = ?, driver_earning = ?, status = 'closed'
        WHERE id = ?
      `;
      db.query(updateOrder, [end_lat, end_lng, distance_km.toFixed(2), price.toFixed(2), driver_earning.toFixed(2), order_id], (err, result) => {
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
app.post('/shifts/:shift_id/summary', (req, res) => {
  const { shift_id } = req.params;

  // نجيب كل الأوردرات المقفولة بتاعة الوردية دي
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
app.listen(PORT, () => {
  console.log(`السيرفر شغال على http://localhost:${PORT}`);
});