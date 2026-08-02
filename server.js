require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { router: adminRouter, addUser } = require('./admin');

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

// ======================
// Routes
// ======================

// Home
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

// Login
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

  console.log('--- Discord Callback ---');
  console.log('Received state:', state);
  console.log('Session state :', req.session.oauthState);

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

    console.log(`✅ Logged in: ${user.username} (${user.id})`);
    res.redirect('/dashboard');
  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).send('Authentication failed.');
  }
});

// Dashboard (with maintenance check)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const maint = getMaintenance();
  if (maint.enabled && req.session.user.id !== ADMIN_ID) {
    return res.send(`
      <!DOCTYPE html>
      <html><body style="background:#05080a;color:#e6edf3;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
        <div style="text-align:center;">
          <h1 style="color:#00ff9c;">Under Maintenance</h1>
          <p style="color:#6b7a8f;">SevnHub is currently under maintenance. Please check back later.</p>
          <br><a href="/logout" style="color:#00ff9c;">Logout</a>
        </div>
      </body></html>
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
// FEEDBACK WEBHOOK
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
