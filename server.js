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
const WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

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

// Admin routes
app.use('/admin', adminRouter);

// ======================
// Helpers
// ======================
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

function ensureDataDir() {
  const dir = path.join(__dirname, 'data');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

const TICKETS_FILE = path.join(__dirname, 'data', 'tickets.json');
const CHAT_FILE = path.join(__dirname, 'data', 'chat.json');
const MAINTENANCE_FILE = path.join(__dirname, 'data', 'maintenance.json');
const GIVEAWAYS_FILE = path.join(__dirname, 'data', 'giveaways.json');
const LOGS_FILE = path.join(__dirname, 'data', 'logs.json');
const IP_LOGS_FILE = path.join(__dirname, 'data', 'ip_logs.json');
const pluginsDir = path.join(__dirname, 'public', 'plugins');

if (!fs.existsSync(pluginsDir)) fs.mkdirSync(pluginsDir, { recursive: true });

function getTickets() {
  try {
    if (!fs.existsSync(TICKETS_FILE)) return [];
    return JSON.parse(fs.readFileSync(TICKETS_FILE, 'utf8'));
  } catch { return []; }
}

function saveTickets(tickets) {
  ensureDataDir();
  fs.writeFileSync(TICKETS_FILE, JSON.stringify(tickets, null, 2));
}

function getChat() {
  try {
    if (!fs.existsSync(CHAT_FILE)) return [];
    return JSON.parse(fs.readFileSync(CHAT_FILE, 'utf8'));
  } catch { return []; }
}

function saveChat(messages) {
  ensureDataDir();
  fs.writeFileSync(CHAT_FILE, JSON.stringify(messages.slice(-200), null, 2));
}

function getMaintenance() {
  try {
    if (!fs.existsSync(MAINTENANCE_FILE)) return { enabled: false };
    return JSON.parse(fs.readFileSync(MAINTENANCE_FILE, 'utf8'));
  } catch { return { enabled: false }; }
}

function getGiveaways() {
  try {
    if (!fs.existsSync(GIVEAWAYS_FILE)) return [];
    return JSON.parse(fs.readFileSync(GIVEAWAYS_FILE, 'utf8'));
  } catch { return []; }
}

function saveGiveaways(list) {
  ensureDataDir();
  fs.writeFileSync(GIVEAWAYS_FILE, JSON.stringify(list, null, 2));
}

function getLogs() {
  try {
    if (!fs.existsSync(LOGS_FILE)) return [];
    return JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
  } catch { return []; }
}

function addLog(action, user, detail = '') {
  ensureDataDir();
  const logs = getLogs();
  logs.unshift({
    id: Date.now().toString(36),
    action,
    user: user ? (user.global_name || user.username) : 'System',
    userId: user ? user.id : null,
    detail,
    at: new Date().toISOString()
  });
  fs.writeFileSync(LOGS_FILE, JSON.stringify(logs.slice(0, 500), null, 2));
}

function getIpLogs() {
  try {
    if (!fs.existsSync(IP_LOGS_FILE)) return [];
    return JSON.parse(fs.readFileSync(IP_LOGS_FILE, 'utf8'));
  } catch { return []; }
}

function addIpLog(req) {
  if (!req.session.user) return;
  ensureDataDir();
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
  fs.writeFileSync(IP_LOGS_FILE, JSON.stringify(logs.slice(0, 300), null, 2));
}

// IP logging
app.use((req, res, next) => {
  if (req.session?.user) {
    const key = `ip_${req.session.user.id}`;
    if (!req.session[key] || Date.now() - req.session[key] > 5 * 60 * 1000) {
      addIpLog(req);
      req.session[key] = Date.now();
    }
  }
  next();
});

// Auto-reset chat every 1 hour
setInterval(() => {
  ensureDataDir();
  fs.writeFileSync(CHAT_FILE, '[]');
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

// Discord OAuth - Start
app.get('/auth/discord', (req, res) => {
  const state = generateState();
  req.session.oauthState = state;

  req.session.save((err) => {
    if (err) {
      console.error('Session save error:', err);
      return res.status(500).send('Session error. Please try again.');
    }

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: SCOPES.join(' '),
      state: state,
      prompt: 'consent'
    });

    res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
  });
});

// Discord OAuth - Callback
app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!state || !req.session.oauthState || state !== req.session.oauthState) {
    return res.status(403).send(`
      <h2>Invalid state. Possible CSRF attack.</h2>
      <p>Session may have been lost. Please try again.</p>
      <br><a href="/login">← Back to Login</a>
    `);
  }

  delete req.session.oauthState;
  if (!code) return res.status(400).send('No authorization code received.');

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
      console.error('Token Error:', tokenData);
      return res.status(400).send(`
        <h2>Failed to get access token</h2>
        <pre>${JSON.stringify(tokenData, null, 2)}</pre>
        <a href="/login">Try again</a>
      `);
    }

    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    const user = await userResponse.json();

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

// Dashboard + maintenance
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const maint = getMaintenance();
  if (maint.enabled && req.session.user.id !== ADMIN_ID) {
    return res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Under Maintenance — SevnHub</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=Orbitron:wght@700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Outfit', system-ui, sans-serif;
      background: #05080a; color: #e6edf3;
      min-height: 100vh; display: flex; align-items: center;
      justify-content: center; text-align: center; padding: 24px;
    }
    .box { max-width: 420px; }
    .icon {
      width: 72px; height: 72px;
      background: rgba(0, 255, 156, 0.08);
      border: 1px solid rgba(0, 255, 156, 0.15);
      border-radius: 20px; display: flex; align-items: center;
      justify-content: center; font-size: 2rem; margin: 0 auto 24px;
      box-shadow: 0 0 40px rgba(0, 255, 156, 0.1);
    }
    h1 {
      font-family: 'Orbitron', sans-serif; font-size: 1.3rem;
      letter-spacing: 0.08em; color: #00ff9c; margin-bottom: 12px;
    }
    p { color: #6b7a8f; font-size: 0.95rem; line-height: 1.6; margin-bottom: 28px; }
    a {
      display: inline-block; padding: 10px 22px; border-radius: 10px;
      border: 1px solid rgba(0, 255, 156, 0.2);
      background: rgba(0, 255, 156, 0.08); color: #00ff9c;
      text-decoration: none; font-weight: 600; font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="box">
    <div class="icon">🛠️</div>
    <h1>UNDER MAINTENANCE</h1>
    <p>SevnHub is currently under maintenance.<br>Please check back later.</p>
    <a href="/logout">Logout</a>
  </div>
</body>
</html>
    `);
  }

  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API - Me
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.user);
});

// API - Plugins
app.get('/api/plugins', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const dir = path.join(__dirname, 'public', 'plugins');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    return res.json([]);
  }

  try {
    const files = fs.readdirSync(dir);
    const plugins = files.map(file => {
      const fp = path.join(dir, file);
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
      else if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) type = 'Image';
      else if (ext) type = ext.toUpperCase();

      return { name, file, type, size: sizeInMB + ' MB', downloadUrl: `/plugins/${encodeURIComponent(file)}` };
    }).filter(Boolean);

    res.json(plugins);
  } catch (err) {
    console.error(err);
    res.json([]);
  }
});

// API - Raid
app.get('/api/raid', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

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
      else if (['json'].includes(ext)) type = 'JSON';
      else if (['exe', 'dll'].includes(ext)) type = 'Binary';
      else if (ext) type = ext.toUpperCase();

      return { name, file, type, size: sizeInMB + ' MB', downloadUrl: `/raid/${encodeURIComponent(file)}` };
    }).filter(Boolean);

    res.json(tools);
  } catch (err) {
    console.error(err);
    res.json([]);
  }
});

// ======================
// GLOBAL CHAT
// ======================
app.get('/api/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(getChat());
});

app.post('/api/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const maint = getMaintenance();
  if (maint.enabled && req.session.user.id !== ADMIN_ID) {
    return res.status(503).json({ error: 'Chat is under maintenance' });
  }

  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Empty message' });

  const user = req.session.user;
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

// ======================
// FEEDBACK
// ======================
app.post('/api/feedback', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });
  if (!WEBHOOK_URL) return res.status(500).json({ error: 'Webhook not configured' });

  const user = req.session.user;

  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: '📩 New Feedback',
          color: 0x00ff9c,
          fields: [
            { name: 'User', value: `${user.global_name || user.username} (\`${user.id}\`)`, inline: true },
            { name: 'Email', value: user.email || 'N/A', inline: true },
            { name: 'Message', value: message.trim().slice(0, 1000) }
          ],
          timestamp: new Date().toISOString()
        }]
      })
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).json({ error: 'Failed to send feedback' });
  }
});

// ======================
// TICKETS
// ======================
app.post('/api/tickets', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });

  const tickets = getTickets();
  const ticket = {
    id: 'TKT-' + Date.now().toString(36).toUpperCase(),
    userId: req.session.user.id,
    username: req.session.user.global_name || req.session.user.username,
    avatar: req.session.user.avatar,
    subject: subject.trim().slice(0, 100),
    status: 'open',
    createdAt: new Date().toISOString(),
    messages: [{
      from: 'user',
      userId: req.session.user.id,
      username: req.session.user.global_name || req.session.user.username,
      text: message.trim().slice(0, 2000),
      at: new Date().toISOString()
    }]
  };

  tickets.unshift(ticket);
  saveTickets(tickets);
  res.json(ticket);
});

app.get('/api/tickets', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  const tickets = getTickets();
  if (req.session.user.id === ADMIN_ID) return res.json(tickets);
  res.json(tickets.filter(t => t.userId === req.session.user.id));
});

app.get('/api/tickets/:id', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  const ticket = getTickets().find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });
  if (req.session.user.id !== ADMIN_ID && ticket.userId !== req.session.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json(ticket);
});

app.post('/api/tickets/:id/reply', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const tickets = getTickets();
  const ticket = tickets.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });

  const isAdmin = req.session.user.id === ADMIN_ID;
  const isOwner = ticket.userId === req.session.user.id;
  if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Access denied' });

  ticket.messages.push({
    from: isAdmin ? 'admin' : 'user',
    userId: req.session.user.id,
    username: req.session.user.global_name || req.session.user.username,
    text: message.trim().slice(0, 2000),
    at: new Date().toISOString()
  });

  if (isAdmin) ticket.status = 'answered';
  saveTickets(tickets);
  res.json(ticket);
});

app.post('/api/tickets/:id/close', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const tickets = getTickets();
  const ticket = tickets.find(t => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });

  const isAdmin = req.session.user.id === ADMIN_ID;
  if (!isAdmin && ticket.userId !== req.session.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }

  ticket.status = 'closed';
  saveTickets(tickets);
  res.json(ticket);
});

app.delete('/api/tickets/clear', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.id !== ADMIN_ID) return res.status(403).json({ error: 'Admin only' });
  saveTickets([]);
  res.json({ success: true });
});

app.delete('/api/tickets/clear-closed', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.id !== ADMIN_ID) return res.status(403).json({ error: 'Admin only' });
  const list = getTickets().filter(t => t.status !== 'closed');
  saveTickets(list);
  res.json({ success: true, remaining: list.length });
});

// ======================
// GIVEAWAYS
// ======================
app.get('/api/giveaways', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

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
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.id !== ADMIN_ID) return res.status(403).json({ error: 'Only admin can create giveaways' });

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
    createdBy: req.session.user.id,
    createdAt: new Date().toISOString(),
    endsAt: new Date(Date.now() + mins * 60 * 1000).toISOString(),
    winnerCount: winners,
    status: 'active',
    entries: [],
    winners: []
  };

  list.unshift(giveaway);
  saveGiveaways(list);
  addLog('create_giveaway', req.session.user, giveaway.title);
  res.json(giveaway);
});

app.post('/api/giveaways/:id/enter', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const list = getGiveaways();
  const g = list.find(x => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Giveaway not found' });
  if (g.status !== 'active') return res.status(400).json({ error: 'Giveaway has ended' });
  if (new Date(g.endsAt).getTime() < Date.now()) return res.status(400).json({ error: 'Giveaway has ended' });

  if (g.entries.find(e => e.userId === req.session.user.id)) {
    return res.status(400).json({ error: 'You already entered' });
  }

  g.entries.push({
    userId: req.session.user.id,
    username: req.session.user.global_name || req.session.user.username,
    avatar: req.session.user.avatar,
    enteredAt: new Date().toISOString()
  });

  saveGiveaways(list);
  res.json({ success: true, entries: g.entries.length });
});

app.get('/api/giveaways/:id/entries', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

  const list = getGiveaways();
  const g = list.find(x => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Not found' });

  if (req.session.user.id !== ADMIN_ID && req.session.user.id !== g.createdBy) {
    return res.status(403).json({ error: 'Access denied' });
  }

  res.json(g.entries);
});

app.post('/api/giveaways/:id/end', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.id !== ADMIN_ID) return res.status(403).json({ error: 'Admin only' });

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
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.id !== ADMIN_ID) return res.status(403).json({ error: 'Admin only' });

  const list = getGiveaways().filter(g => g.status === 'active');
  saveGiveaways(list);
  res.json({ success: true, remaining: list.length });
});

// ======================
// ADMIN APIs
// ======================
app.get('/api/admin/users', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  res.json(getUsers());
});

app.delete('/api/admin/users/:id', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  const users = getUsers().filter(u => u.id !== req.params.id);
  saveUsers(users);
  addLog('delete_user', req.session.user, `Deleted ${req.params.id}`);
  res.json({ success: true });
});

app.get('/api/admin/maintenance', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  res.json(getMaintenance());
});

app.post('/api/admin/maintenance', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  const enabled = !!req.body.enabled;
  ensureDataDir();
  fs.writeFileSync(MAINTENANCE_FILE, JSON.stringify({ enabled }, null, 2));
  addLog('maintenance', req.session.user, enabled ? 'ON' : 'OFF');
  res.json({ enabled });
});

app.get('/api/admin/logs', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  res.json(getLogs());
});

app.delete('/api/admin/logs', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  ensureDataDir();
  fs.writeFileSync(LOGS_FILE, '[]');
  res.json({ success: true });
});

app.get('/api/admin/ip-logs', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  res.json(getIpLogs());
});

app.delete('/api/admin/ip-logs', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  ensureDataDir();
  fs.writeFileSync(IP_LOGS_FILE, '[]');
  res.json({ success: true });
});

// Delete plugin (no multer needed)
app.delete('/api/admin/plugins/:filename', (req, res) => {
  if (!req.session.user || req.session.user.id !== ADMIN_ID) {
    return res.status(403).json({ error: 'Admin only' });
  }
  const file = path.basename(req.params.filename);
  const fp = path.join(pluginsDir, file);
  if (fs.existsSync(fp)) {
    fs.unlinkSync(fp);
    addLog('delete_plugin', req.session.user, file);
  }
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
});
