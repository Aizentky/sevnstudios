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

// ======================
// Routes
// ======================

// Home
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Discord OAuth - Start
app.get('/auth/discord', (req, res) => {
  const state = generateState();
  req.session.oauthState = state;

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

// Discord OAuth - Callback
app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;

  console.log('--- Discord Callback ---');
  console.log('Code:', code ? 'received' : 'MISSING');
  console.log('State match:', state === req.session.oauthState);
  console.log('Redirect URI:', REDIRECT_URI);
  console.log('Client ID:', CLIENT_ID);

  if (!state || state !== req.session.oauthState) {
    return res.status(403).send('Invalid state. Possible CSRF attack.');
  }
  delete req.session.oauthState;

  if (!code) {
    return res.status(400).send('No authorization code received.');
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI
      })
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('❌ Token Error:', tokenData);
      return res.status(400).send(`
        <h2>Failed to get access token</h2>
        <pre>${JSON.stringify(tokenData, null, 2)}</pre>
        <p><b>Redirect URI used:</b> ${REDIRECT_URI}</p>
        <p><b>Client ID:</b> ${CLIENT_ID}</p>
        <br>
        <a href="/login">Try again</a>
      `);
    }

    // Get user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`
      }
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

    // Save session
    req.session.user = userData;

    // Save permanently
    addUser(userData);

    console.log(`✅ User logged in: ${user.username} (${user.id})`);
    res.redirect('/dashboard');

  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).send('Authentication failed.');
  }
});

// ======================
// Dashboard
// ======================
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API - Get current user
app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  res.json(req.session.user);
});

// API - List plugins from /public/plugins
app.get('/api/plugins', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const pluginsDir = path.join(__dirname, 'public', 'plugins');

  if (!fs.existsSync(pluginsDir)) {
    fs.mkdirSync(pluginsDir, { recursive: true });
    return res.json([]);
  }

  try {
    const files = fs.readdirSync(pluginsDir);

    const plugins = files.map(file => {
      const filePath = path.join(pluginsDir, file);
      const stats = fs.statSync(filePath);

      // Skip folders
      if (stats.isDirectory()) return null;

      const ext = path.extname(file).toLowerCase().replace('.', '');
      const name = path.basename(file, path.extname(file));

      // File size in MB
      const sizeInMB = (stats.size / (1024 * 1024)).toFixed(2);

      // Detect type
      let type = 'File';
      if (['js', 'ts', 'jsx', 'tsx'].includes(ext)) type = 'JavaScript';
      else if (['py'].includes(ext)) type = 'Python';
      else if (['zip', 'rar', '7z'].includes(ext)) type = 'Archive';
      else if (['json'].includes(ext)) type = 'JSON';
      else if (['txt', 'md'].includes(ext)) type = 'Text';
      else if (['dll', 'exe'].includes(ext)) type = 'Binary';
      else if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) type = 'Image';
      else if (ext) type = ext.toUpperCase();

      return {
        name: name,
        file: file,
        type: type,
        size: sizeInMB + ' MB',
        sizeBytes: stats.size,
        downloadUrl: `/plugins/${encodeURIComponent(file)}`
      };
    }).filter(Boolean);

    res.json(plugins);
  } catch (err) {
    console.error('Error reading plugins:', err);
    res.json([]);
  }
});

// API - List raid tools from /public/raid
app.get('/api/raid', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const raidDir = path.join(__dirname, 'public', 'raid');

  if (!fs.existsSync(raidDir)) {
    fs.mkdirSync(raidDir, { recursive: true });
    return res.json([]);
  }

  try {
    const files = fs.readdirSync(raidDir);

    const tools = files.map(file => {
      const filePath = path.join(raidDir, file);
      const stats = fs.statSync(filePath);

      // Skip folders
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
      else if (['txt', 'md'].includes(ext)) type = 'Text';
      else if (ext) type = ext.toUpperCase();

      return {
        name: name,
        file: file,
        type: type,
        size: sizeInMB + ' MB',
        downloadUrl: `/raid/${encodeURIComponent(file)}`
      };
    }).filter(Boolean);

    res.json(tools);
  } catch (err) {
    console.error('Error reading raid tools:', err);
    res.json([]);
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ======================
// Start server
// ======================
app.listen(PORT, () => {
  console.log(`🚀 Server running on ${BASE_URL}`);
});