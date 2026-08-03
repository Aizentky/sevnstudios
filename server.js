require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { router: adminRouter, addUser, getUsers, saveUsers } = require('./admin');

const app = express();
const PORT = process.env.PORT || 3000;

// ======================
// Config
// ======================
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/auth/discord/callback`;
const SCOPES = ['identify', 'email'];
const ADMIN_ID = process.env.ADMIN_DISCORD_ID || '1504098102171406510';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

// ======================
// Trust proxy (Render)
// ======================
app.set('trust proxy', 1);

// ======================
// Middleware
// ======================
app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

app.use('/admin', adminRouter);

// ======================
// Helpers
// ======================
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJSON(file, data) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const TICKETS_FILE = path.join(DATA_DIR, 'tickets.json');
const CHAT_FILE = path.join(DATA_DIR, 'chat.json');
const MAINTENANCE_FILE = path.join(DATA_DIR, 'maintenance.json');
const GIVEAWAYS_FILE = path.join(DATA_DIR, 'giveaways.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');
const IP_LOGS_FILE = path.join(DATA_DIR, 'ip_logs.json');
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, 'announcements.json');
const BANS_FILE = path.join(DATA_DIR, 'bans.json');
const CODES_FILE = path.join(DATA_DIR, 'codes.json');
const FEEDBACK_FILE = path.join(DATA_DIR, 'feedback.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

const pluginsDir = path.join(__dirname, 'public', 'plugins');
if (!fs.existsSync(pluginsDir)) fs.mkdirSync(pluginsDir, { recursive: true });

function getTickets() { return readJSON(TICKETS_FILE, []); }
function saveTickets(d) { writeJSON(TICKETS_FILE, d); }
function getChat() { return readJSON(CHAT_FILE, []); }
function saveChat(d) { writeJSON(CHAT_FILE, d.slice(-200)); }
function getMaintenance() { return readJSON(MAINTENANCE_FILE, { enabled: false }); }
function getGiveaways() { return readJSON(GIVEAWAYS_FILE, []); }
function saveGiveaways(d) { writeJSON(GIVEAWAYS_FILE, d); }
function getLogs() { return readJSON(LOGS_FILE, []); }
function getIpLogs() { return readJSON(IP_LOGS_FILE, []); }
function getAnnouncements() { return readJSON(ANNOUNCEMENTS_FILE, []); }
function saveAnnouncements(d) { writeJSON(ANNOUNCEMENTS_FILE, d); }
function getBans() { return readJSON(BANS_FILE, []); }
function saveBans(d) { writeJSON(BANS_FILE, d); }
function getCodes() { return readJSON(CODES_FILE, []); }
function saveCodes(d) { writeJSON(CODES_FILE, d); }
function getFeedback() { return readJSON(FEEDBACK_FILE, []); }
function saveFeedback(d) { writeJSON(FEEDBACK_FILE, d.slice(0, 300)); }
function getSettings() {
  return readJSON(SETTINGS_FILE, {
    siteName: 'SevnHub',
    raidPass: 'sevntools2026paid',
    maintMsg: 'SevnHub is currently under maintenance. Please check back later.'
  });
}
function saveSettings(d) { writeJSON(SETTINGS_FILE, d); }

function addLog(action, user, detail = '') {
  const logs = getLogs();
  logs.unshift({
    id: Date.now().toString(36),
    action,
    user: user ? (user.global_name || user.username) : 'System',
    userId: user ? user.id : null,
    detail,
    at: new Date().toISOString()
  });
  writeJSON(LOGS_FILE, logs.slice(0, 500));
}

function isBanned(userId) {
  return getBans().some(b => b.userId === userId);
}

function requireAuth(req, res) {
  if (!req.session.user) {
    res.status(401).json({ error: 'Not logged in' });
    return null;
  }
  if (isBanned(req.session.user.id)) {
    req.session.destroy(() => {});
    res.status(403).json({ error: 'You are banned' });
    return null;
  }
  return req.session.user;
}

function requireAdmin(req, res) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (user.id !== ADMIN_ID) {
    res.status(403).json({ error: 'Admin only' });
    return null;
  }
  return user;
}

// IP logging
app.use((req, res, next) => {
  if (req.session?.user) {
    const key = `ip_${req.session.user.id}`;
    if (!req.session[key] || Date.now() - req.session[key] > 5 * 60 * 1000) {
      const logs = getIpLogs();
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
      logs.unshift({
        id: Date.now().toString(36),
        userId: req.session.user.id,
        username: req.session.user.global_name || req.session.user.username,
        ip,
        path: req.originalUrl,
        at: new Date().toISOString()
      });
      writeJSON(IP_LOGS_FILE, logs.slice(0, 300));
      req.session[key] = Date.now();
    }
  }
  next();
});

// Hourly chat reset
setInterval(() => {
  writeJSON(CHAT_FILE, []);
  console.log('🧹 Chat cleared (hourly reset)');
}, 60 * 60 * 1000);

// ======================
// Routes
// ======================
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// OAuth start
app.get('/auth/discord', (req, res) => {
  const state = generateState();
  req.session.oauthState = state;
  req.session.save((err) => {
    if (err) return res.status(500).send('Session error.');
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: SCOPES.join(' '),
      state,
      prompt: 'consent'
    });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });
});

// OAuth callback
app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!state || !req.session.oauthState || state !== req.session.oauthState) {
    return res.status(403).send(`
      <h2>Invalid state. Possible CSRF attack.</h2>
      <p><a href="/login">← Back to Login</a></p>
    `);
  }
  delete req.session.oauthState;
  if (!code) return res.status(400).send('No authorization code.');

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI
      })
    });
    const tokenData = await tokenResponse.json();
    if (tokenData.error) {
      return res.status(400).send(`<h2>Token error</h2><pre>${JSON.stringify(tokenData, null, 2)}</pre><a href="/login">Try again</a>`);
    }

    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userResponse.json();

    if (isBanned(user.id)) {
      return res.status(403).send(`
        <h2>You are banned from SevnHub</h2>
        <p><a href="/login">Back</a></p>
      `);
    }

    const userData = {
      id: user.id,
      username: user.username,
      discriminator: user.discriminator,
      global_name: user.global_name,
      avatar: user.avatar,
      email: user.email
    };

    req.session.user = userData;
    addUser(userData);
    addLog('login', userData);
    console.log(`✅ Logged in: ${user.username} (${user.id})`);
    res.redirect('/dashboard');
  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).send('Authentication failed.');
  }
});

// Dashboard
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (isBanned(req.session.user.id)) {
    req.session.destroy(() => res.redirect('/login'));
    return;
  }

  const maint = getMaintenance();
  if (maint.enabled && req.session.user.id !== ADMIN_ID) {
    const settings = getSettings();
    const msg = settings.maintMsg || 'SevnHub is currently under maintenance.';
    return res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Under Maintenance</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=Orbitron:wght@700&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:Outfit,system-ui,sans-serif;background:#05080a;color:#e6edf3;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px}
    .box{max-width:420px}
    .icon{width:72px;height:72px;background:rgba(0,255,156,.08);border:1px solid rgba(0,255,156,.15);border-radius:20px;display:flex;align-items:center;justify-content:center;font-size:2rem;margin:0 auto 24px;box-shadow:0 0 40px rgba(0,255,156,.1)}
    h1{font-family:Orbitron,sans-serif;font-size:1.3rem;letter-spacing:.08em;color:#00ff9c;margin-bottom:12px}
    p{color:#6b7a8f;font-size:.95rem;line-height:1.6;margin-bottom:28px}
    a{display:inline-block;padding:10px 22px;border-radius:10px;border:1px solid rgba(0,255,156,.2);background:rgba(0,255,156,.08);color:#00ff9c;text-decoration:none;font-weight:600;font-size:.85rem}
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">🛠️</div>
    <h1>UNDER MAINTENANCE</h1>
    <p>${msg.replace(/</g, '&lt;')}</p>
    <a href="/logout">Logout</a>
  </div>
</body>
</html>`);
  }

  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API - Me
app.get('/api/me', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  res.json(user);
});

// ======================
// PLUGINS / RAID
// ======================
app.get('/api/plugins', (req, res) => {
  if (!requireAuth(req, res)) return;
  if (!fs.existsSync(pluginsDir)) {
    fs.mkdirSync(pluginsDir, { recursive: true });
    return res.json([]);
  }
  try {
    const files = fs.readdirSync(pluginsDir);
    const plugins = files.map(file => {
      const fp = path.join(pluginsDir, file);
      const stats = fs.statSync(fp);
      if (stats.isDirectory()) return null;
      const ext = path.extname(file).toLowerCase().replace('.', '');
      const name = path.basename(file, path.extname(file));
      const sizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
      let type = 'File';
      if (['js', 'ts', 'jsx', 'tsx'].includes(ext)) type = 'JavaScript';
      else if (['py'].includes(ext)) type = 'Python';
      else if (['zip', 'rar', '7z'].includes(ext)) type = 'Archive';
      else if (['json'].includes(ext)) type = 'JSON';
      else if (['txt', 'md'].includes(ext)) type = 'Text';
      else if (['dll', 'exe'].includes(ext)) type = 'Binary';
      else if (ext) type = ext.toUpperCase();
      return { name, file, type, size: sizeInMB + ' MB', downloadUrl: `/plugins/${encodeURIComponent(file)}` };
    }).filter(Boolean);
    res.json(plugins);
  } catch {
    res.json([]);
  }
});

app.get('/api/raid', (req, res) => {
  if (!requireAuth(req, res)) return;
  const dir = path.join(__dirname, 'public', 'raid');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    return res.json([]);
  }
  try {
    const files = fs.readdirSync(dir);
    const tools = files.map(file => {
      const fp = path.join(dir, file);
      const stats = fs.statSync(fp);
      if (stats.isDirectory()) return null;
      const ext = path.extname(file).toLowerCase().replace('.', '');
      const name = path.basename(file, path.extname(file));
      const sizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
      let type = 'File';
      if (['js', 'ts'].includes(ext)) type = 'JavaScript';
      else if (['py'].includes(ext)) type = 'Python';
      else if (['zip', 'rar', '7z'].includes(ext)) type = 'Archive';
      else if (ext) type = ext.toUpperCase();
      return { name, file, type, size: sizeInMB + ' MB', downloadUrl: `/raid/${encodeURIComponent(file)}` };
    }).filter(Boolean);
    res.json(tools);
  } catch {
    res.json([]);
  }
});

app.delete('/api/admin/plugins/:filename', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const file = path.basename(req.params.filename);
  const fp = path.join(pluginsDir, file);
  if (fs.existsSync(fp)) {
    fs.unlinkSync(fp);
    addLog('delete_plugin', req.session.user, file);
  }
  res.json({ success: true });
});

// ======================
// CHAT
// ======================
app.get('/api/chat', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(getChat());
});

app.post('/api/chat', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const maint = getMaintenance();
  if (maint.enabled && user.id !== ADMIN_ID) {
    return res.status(503).json({ error: 'Chat is under maintenance' });
  }
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Empty message' });
  const messages = getChat();
  messages.push({
    id: Date.now().toString(36),
    userId: user.id,
    username: user.global_name || user.username,
    avatar: user.avatar,
    text: message.trim().slice(0, 500),
    at: new Date().toISOString()
  });
  saveChat(messages);
  res.json({ success: true });
});

app.delete('/api/admin/chat', (req, res) => {
  if (!requireAdmin(req, res)) return;
  writeJSON(CHAT_FILE, []);
  addLog('clear_chat', req.session.user);
  res.json({ success: true });
});

// ======================
// FEEDBACK (in-app)
// ======================
app.post('/api/feedback', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
  const list = getFeedback();
  list.unshift({
    id: Date.now().toString(36),
    userId: user.id,
    username: user.global_name || user.username,
    avatar: user.avatar,
    text: message.trim().slice(0, 1000),
    at: new Date().toISOString()
  });
  saveFeedback(list);
  res.json({ success: true });
});

app.get('/api/admin/feedback', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getFeedback());
});

app.delete('/api/admin/feedback/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = getFeedback().filter(f => f.id !== req.params.id);
  saveFeedback(list);
  res.json({ success: true });
});

// ======================
// ANNOUNCEMENTS
// ======================
app.get('/api/announcements', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = getAnnouncements();
  list.sort((a, b) => (b.pinned - a.pinned) || (new Date(b.at) - new Date(a.at)));
  res.json(list);
});

app.post('/api/admin/announcements', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { title, body, pinned } = req.body;
  if (!title || !body) return res.status(400).json({ error: 'Title and body required' });
  const list = getAnnouncements();
  const item = {
    id: Date.now().toString(36),
    title: title.trim().slice(0, 120),
    body: body.trim().slice(0, 2000),
    pinned: !!pinned,
    at: new Date().toISOString()
  };
  list.unshift(item);
  saveAnnouncements(list);
  addLog('create_announcement', req.session.user, item.title);
  res.json(item);
});

app.delete('/api/admin/announcements/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = getAnnouncements().filter(a => a.id !== req.params.id);
  saveAnnouncements(list);
  addLog('delete_announcement', req.session.user, req.params.id);
  res.json({ success: true });
});

// ======================
// BANS
// ======================
app.get('/api/admin/bans', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getBans());
});

app.post('/api/admin/bans', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { userId, reason } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (userId === ADMIN_ID) return res.status(400).json({ error: 'Cannot ban owner' });
  const bans = getBans();
  if (bans.find(b => b.userId === userId)) return res.status(400).json({ error: 'Already banned' });
  bans.unshift({
    userId: String(userId).trim(),
    reason: (reason || '').trim().slice(0, 200),
    at: new Date().toISOString()
  });
  saveBans(bans);
  addLog('ban_user', req.session.user, userId);
  res.json({ success: true });
});

app.delete('/api/admin/bans/:userId', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const bans = getBans().filter(b => b.userId !== req.params.userId);
  saveBans(bans);
  addLog('unban_user', req.session.user, req.params.userId);
  res.json({ success: true });
});

// ======================
// CODES
// ======================
app.get('/api/admin/codes', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getCodes());
});

app.post('/api/admin/codes', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { code, note, maxUses } = req.body;
  if (!code || !code.trim()) return res.status(400).json({ error: 'Code required' });
  const codes = getCodes();
  const normalized = code.trim().toUpperCase();
  if (codes.find(c => c.code === normalized)) return res.status(400).json({ error: 'Code already exists' });
  const item = {
    id: Date.now().toString(36),
    code: normalized,
    note: (note || '').trim().slice(0, 200),
    maxUses: Math.max(1, parseInt(maxUses) || 1),
    uses: 0,
    at: new Date().toISOString()
  };
  codes.unshift(item);
  saveCodes(codes);
  addLog('create_code', req.session.user, item.code);
  res.json(item);
});

app.delete('/api/admin/codes/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const codes = getCodes().filter(c => c.id !== req.params.id);
  saveCodes(codes);
  addLog('delete_code', req.session.user, req.params.id);
  res.json({ success: true });
});

// ======================
// SETTINGS
// ======================
app.get('/api/admin/settings', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getSettings());
});

app.post('/api/admin/settings', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const current = getSettings();
  const next = {
    siteName: (req.body.siteName || current.siteName || 'SevnHub').trim().slice(0, 50),
    raidPass: (req.body.raidPass || current.raidPass || 'sevntools2026paid').trim().slice(0, 100),
    maintMsg: (req.body.maintMsg || current.maintMsg || '').trim().slice(0, 500)
  };
  saveSettings(next);
  addLog('update_settings', req.session.user);
  res.json(next);
});

// Public raid password check helper (optional)
app.get('/api/settings/public', (req, res) => {
  if (!requireAuth(req, res)) return;
  const s = getSettings();
  res.json({ siteName: s.siteName });
});

// ======================
// STATS
// ======================
app.get('/api/admin/stats', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const users = getUsers();
  const tickets = getTickets();
  const giveaways = getGiveaways();
  const chat = getChat();
  const bans = getBans();
  const feedback = getFeedback();
  res.json({
    users: users.length,
    openTickets: tickets.filter(t => t.status !== 'closed').length,
    activeGiveaways: giveaways.filter(g => g.status === 'active').length,
    chatMessages: chat.length,
    bans: bans.length,
    feedback: feedback.length
  });
});

// ======================
// TICKETS
// ======================
app.post('/api/tickets', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });
  const tickets = getTickets();
  const ticket = {
    id: 'TKT-' + Date.now().toString(36).toUpperCase(),
    userId: user.id,
    username: user.global_name || user.username,
    avatar: user.avatar,
    subject: subject.trim().slice(0, 100),
    status: 'open',
    createdAt: new Date().toISOString(),
    messages: [{
      from: 'user',
      userId: user.id,
      username: user.global_name || user.username,
      text: message.trim().slice(0, 2000),
      at: new Date().toISOString()
    }]
  };
  tickets.unshift(ticket);
  saveTickets(tickets);
  res.json(ticket);
});

app.get('/api/tickets', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const tickets = getTickets();
  if (user.id === ADMIN_ID) return res.json(tickets);
  res.json(tickets.filter(t => t.userId === user.id));
});

app.get('/api/tickets/:id', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const ticket = getTickets().find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });
  if (user.id !== ADMIN_ID && ticket.userId !== user.id) return res.status(403).json({ error: 'Access denied' });
  res.json(ticket);
});

app.post('/api/tickets/:id/reply', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
  const tickets = getTickets();
  const ticket = tickets.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });
  const isAdmin = user.id === ADMIN_ID;
  if (!isAdmin && ticket.userId !== user.id) return res.status(403).json({ error: 'Access denied' });
  ticket.messages.push({
    from: isAdmin ? 'admin' : 'user',
    userId: user.id,
    username: user.global_name || user.username,
    text: message.trim().slice(0, 2000),
    at: new Date().toISOString()
  });
  if (isAdmin) ticket.status = 'answered';
  saveTickets(tickets);
  res.json(ticket);
});

app.post('/api/tickets/:id/close', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const tickets = getTickets();
  const ticket = tickets.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });
  if (user.id !== ADMIN_ID && ticket.userId !== user.id) return res.status(403).json({ error: 'Access denied' });
  ticket.status = 'closed';
  saveTickets(tickets);
  res.json(ticket);
});

app.delete('/api/tickets/clear', (req, res) => {
  if (!requireAdmin(req, res)) return;
  saveTickets([]);
  res.json({ success: true });
});

app.delete('/api/tickets/clear-closed', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = getTickets().filter(t => t.status !== 'closed');
  saveTickets(list);
  res.json({ success: true, remaining: list.length });
});

// ======================
// GIVEAWAYS
// ======================
app.get('/api/giveaways', (req, res) => {
  if (!requireAuth(req, res)) return;
  const now = Date.now();
  let list = getGiveaways();
  list = list.map(g => {
    if (g.status === 'active' && new Date(g.endsAt).getTime() < now) {
      g.status = 'ended';
      if (!g.winners || !g.winners.length) {
        const shuffled = [...g.entries].sort(() => Math.random() - 0.5);
        g.winners = shuffled.slice(0, g.winnerCount).map(e => ({
          userId: e.userId,
          username: e.username,
          avatar: e.avatar
        }));
      }
    }
    return g;
  });
  saveGiveaways(list);
  res.json(list);
});

app.post('/api/giveaways', (req, res) => {
  const user = requireAdmin(req, res);
  if (!user) return;
  const { title, description, durationMinutes, winnerCount } = req.body;
  if (!title || !description || !durationMinutes) {
    return res.status(400).json({ error: 'Title, description and duration required' });
  }
  const mins = Math.max(1, parseInt(durationMinutes) || 60);
  const winners = Math.max(1, parseInt(winnerCount) || 1);
  const list = getGiveaways();
  const giveaway = {
    id: 'GW-' + Date.now().toString(36).toUpperCase(),
    title: title.trim().slice(0, 100),
    description: description.trim().slice(0, 500),
    createdBy: user.id,
    createdAt: new Date().toISOString(),
    endsAt: new Date(Date.now() + mins * 60 * 1000).toISOString(),
    winnerCount: winners,
    status: 'active',
    entries: [],
    winners: []
  };
  list.unshift(giveaway);
  saveGiveaways(list);
  addLog('create_giveaway', user, giveaway.title);
  res.json(giveaway);
});

app.post('/api/giveaways/:id/enter', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const list = getGiveaways();
  const g = list.find(x => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Giveaway not found' });
  if (g.status !== 'active') return res.status(400).json({ error: 'Giveaway has ended' });
  if (new Date(g.endsAt).getTime() < Date.now()) return res.status(400).json({ error: 'Giveaway has ended' });
  if (g.entries.find(e => e.userId === user.id)) return res.status(400).json({ error: 'You already entered' });
  g.entries.push({
    userId: user.id,
    username: user.global_name || user.username,
    avatar: user.avatar,
    enteredAt: new Date().toISOString()
  });
  saveGiveaways(list);
  res.json({ success: true, entries: g.entries.length });
});

app.get('/api/giveaways/:id/entries', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const g = getGiveaways().find(x => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });
  if (user.id !== ADMIN_ID && user.id !== g.createdBy) return res.status(403).json({ error: 'Access denied' });
  res.json(g.entries);
});

app.post('/api/giveaways/:id/end', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = getGiveaways();
  const g = list.find(x => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });
  g.status = 'ended';
  const shuffled = [...g.entries].sort(() => Math.random() - 0.5);
  g.winners = shuffled.slice(0, g.winnerCount).map(e => ({
    userId: e.userId,
    username: e.username,
    avatar: e.avatar
  }));
  saveGiveaways(list);
  addLog('end_giveaway', req.session.user, g.title);
  res.json(g);
});

app.delete('/api/giveaways/clear-ended', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const list = getGiveaways().filter(g => g.status === 'active');
  saveGiveaways(list);
  res.json({ success: true, remaining: list.length });
});

// ======================
// ADMIN USERS / MAINT / LOGS / IP
// ======================
app.get('/api/admin/users', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getUsers());
});

app.delete('/api/admin/users/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  if (req.params.id === ADMIN_ID) return res.status(400).json({ error: 'Cannot delete owner' });
  const users = getUsers().filter(u => u.id !== req.params.id);
  saveUsers(users);
  addLog('delete_user', req.session.user, req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/maintenance', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getMaintenance());
});

app.post('/api/admin/maintenance', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const enabled = !!req.body.enabled;
  writeJSON(MAINTENANCE_FILE, { enabled });
  addLog('maintenance', req.session.user, enabled ? 'ON' : 'OFF');
  res.json({ enabled });
});

app.get('/api/admin/logs', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getLogs());
});

app.delete('/api/admin/logs', (req, res) => {
  if (!requireAdmin(req, res)) return;
  writeJSON(LOGS_FILE, []);
  res.json({ success: true });
});

app.get('/api/admin/ip-logs', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(getIpLogs());
});

app.delete('/api/admin/ip-logs', (req, res) => {
  if (!requireAdmin(req, res)) return;
  writeJSON(IP_LOGS_FILE, []);
  res.json({ success: true });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ======================
// Start
// ======================
app.listen(PORT, () => {
  console.log(`🚀 Server running on ${BASE_URL}`);
  console.log(`🔗 Redirect URI: ${REDIRECT_URI}`);
  console.log(`📁 Data dir: ${DATA_DIR}`);
});
