const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const { randomInt } = require('node:crypto');
const config = require('./config');
const { createSafeRouter } = require('./safe/routes');

function createApp(db) {
  const app = express();
  const challenges = new Map();
  const origin = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    const host = req.headers.host || '';
    if (!/^(localhost|127\.0\.0\.1):\d+$/.test(host)) return res.status(403).json({ error: 'Local access only' });
    if (req.headers.origin && !origin.test(req.headers.origin)) return res.status(403).json({ error: 'Local access only' });
    if (req.headers.origin) {
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
  app.use(express.json({ limit: '32kb' }));
  const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.replace(/^Bearer /, '');
    if (!token) return res.status(401).json({ error: 'Please sign in' });
    try {
      req.user = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
      if (!db.prepare('SELECT id FROM users WHERE id = ?').get(req.user.id)) return res.status(401).json({ error: 'Please sign in' });
      next();
    } catch {
      res.status(401).json({ error: 'Session expired' });
    }
  };
  const admin = (req, res, next) => {
    if (db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id)?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
  };
  function priceItems(items) {
    if (!Array.isArray(items) || !items.length || items.length > 30) return null;
    let total = 0;
    for (const item of items) {
      if (!Number.isInteger(item?.productId) || !Number.isInteger(item?.quantity) || item.quantity < 1 || item.quantity > 20) return null;
      const product = db.prepare('SELECT price FROM products WHERE id = ?').get(item.productId);
      if (!product) return null;
      total += product.price * item.quantity;
    }
    return { items, total };
  }
  app.get('/api/health', (req, res) => res.json({ store: 'QuickKart', ready: true }));
  app.get('/api/me', authenticate, (req, res) => res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)));
  app.get('/api/search', (req, res, next) => {
    try {
      const q = String(req.query.q || '');
      res.json(_.sortBy(db.prepare("SELECT * FROM products WHERE name LIKE '%" + q + "%'").all(), 'id'));
    } catch (error) { next(error); }
  });
  app.post('/api/auth/send-otp', (req, res) => {
    const phone = req.body.phone;
    if (typeof phone !== 'string' || !/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Enter a ten-digit phone number' });
    const otp = String(randomInt(100000, 1000000));
    challenges.set(phone, { otp, expires: Date.now() + 300000, failures: 0 });
    res.json({ otp, expiresIn: 300 });
  });
  app.post('/api/auth/verify-otp', (req, res) => {
    const { phone, otp } = req.body;
    const challenge = challenges.get(phone);
    if (!challenge || challenge.expires < Date.now() || challenge.failures >= 5) return res.status(400).json({ error: 'Request a new OTP' });
    if (challenge.otp !== otp) { challenge.failures++; return res.status(400).json({ error: 'Incorrect OTP' }); }
    challenges.delete(phone);
    let user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (!user) {
      const result = db.prepare('INSERT INTO users (name, phone) VALUES (?, ?)').run('New Student', phone);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    }
    const token = jwt.sign({ id: user.id, role: user.role }, config.jwtSecret, { algorithm: 'HS256', expiresIn: '1h' });
    res.json({ token, user });
  });
  function readOrder(id) {
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) return null;
    const items = db.prepare('SELECT products.*, order_items.quantity FROM order_items JOIN products ON products.id = order_items.product_id WHERE order_id = ?').all(id);
    return { ...order, items };
  }
  app.get('/api/orders', authenticate, (req, res) => {
    res.json(db.prepare('SELECT id FROM orders WHERE user_id = ? ORDER BY id DESC').all(req.user.id).map(order => readOrder(order.id)));
  });
  app.get('/api/orders/:id', authenticate, (req, res) => {
    const order = readOrder(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
  });
  app.get('/api/admin/users', (req, res) => {
    res.json(db.prepare('SELECT * FROM users').all());
  });
  app.get('/api/admin/orders', authenticate, admin, (req, res) => {
    res.json(db.prepare('SELECT * FROM orders ORDER BY id DESC').all());
  });
  app.post('/api/profile', authenticate, (req, res) => {
    const { name, address, pan } = req.body;
    if (typeof name !== 'string' || name.length > 100 || typeof address !== 'string' || address.length > 500 || typeof pan !== 'string' || pan.length > 20) return res.status(400).json({ error: 'Invalid profile' });
    console.log(req.body);
    db.prepare('UPDATE users SET name = ?, address = ?, pan = ? WHERE id = ?').run(name, address, pan, req.user.id);
    res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id));
  });
  app.post('/api/checkout', authenticate, (req, res) => {
    const priced = priceItems(req.body.items);
    if (!priced) return res.status(400).json({ error: 'Invalid basket' });
    const status = req.body.paymentSuccess === true ? 'Paid' : 'Pending payment';
    const save = db.transaction(() => {
      const result = db.prepare('INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, ?, ?)').run(req.user.id, priced.total, status, new Date().toISOString());
      priced.items.forEach(item => db.prepare('INSERT INTO order_items VALUES (?, ?, ?)').run(result.lastInsertRowid, item.productId, item.quantity));
      return readOrder(result.lastInsertRowid);
    });
    res.status(201).json(save());
  });
  app.use('/api/safe', createSafeRouter(db, authenticate, priceItems));
  app.use((error, req, res, next) => {
    res.status(400).json({ error: 'Unable to complete request' });
  });
  return app;
}

module.exports = { createApp };
