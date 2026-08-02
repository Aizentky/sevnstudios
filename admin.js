const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const ALLOWED_ADMIN_ID = '1504098102171406510'; // ← only this Discord ID can access

// Ensure data folder + file exist
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, '[]');
}

// Helpers
function getUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ======================
// Protect Admin - Only specific Discord ID
// ======================
function requireAdmin(req, res, next) {
  // Must be logged in with Discord first
  if (!req.session.user) {
    return res.redirect('/login');
  }

  // Only allow this Discord ID
  if (req.session.user.id !== ALLOWED_ADMIN_ID) {
    return res.status(403).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Access Denied</title>
        <style>
          body {
            font-family: system-ui;
            background: #0a0a0f;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            text-align: center;
          }
          .box {
            background: #14141c;
            padding: 40px;
            border-radius: 16px;
            border: 1px solid #2a2a35;
          }
          h1 { color: #ef4444; margin-bottom: 12px; }
          a { color: #5865F2; }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>Access Denied</h1>
          <p>You are not authorized to view the admin panel.</p>
          <br>
          <a href="/dashboard">← Back to Dashboard</a>
        </div>
      </body>
      </html>
    `);
  }

  next();
}

// ======================
// Admin Dashboard
// ======================
router.get('/', requireAdmin, (req, res) => {
  const users = getUsers();

  const rows = users.map((u, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>
        <img src="${u.avatar 
          ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png` 
          : 'https://cdn.discordapp.com/embed/avatars/0.png'}" 
          width="32" height="32" style="border-radius:50%; vertical-align:middle; margin-right:8px;">
        ${u.global_name || u.username}
      </td>
      <td>${u.username}</td>
      <td><code>${u.id}</code></td>
      <td>${u.email || '—'}</td>
      <td>${new Date(u.joinedAt).toLocaleString()}</td>
      <td>
        <form method="POST" action="/admin/delete/${u.id}" style="display:inline" onsubmit="return confirm('Delete this user?')">
          <button type="submit" style="background:#ef4444;color:white;border:none;padding:4px 10px;border-radius:6px;cursor:pointer;">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Panel - SevnHub</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0f; color: #e5e7eb; padding: 40px 20px; }
        .container { max-width: 1100px; margin: 0 auto; }
        h1 { font-size: 28px; margin-bottom: 8px; }
        .subtitle { color: #9ca3af; margin-bottom: 32px; }
        .stats { display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }
        .stat { background: #14141c; border: 1px solid #2a2a35; border-radius: 12px; padding: 20px 28px; flex: 1; min-width: 140px; }
        .stat-value { font-size: 32px; font-weight: 700; color: #5865F2; }
        .stat-label { color: #9ca3af; font-size: 14px; margin-top: 4px; }
        table { width: 100%; border-collapse: collapse; background: #14141c; border-radius: 12px; overflow: hidden; border: 1px solid #2a2a35; }
        th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid #2a2a35; }
        th { background: #1a1a24; color: #9ca3af; font-weight: 500; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
        tr:last-child td { border-bottom: none; }
        tr:hover { background: #1a1a24; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
        .btn { background: #5865F2; color: white; border: none; padding: 10px 18px; border-radius: 8px; text-decoration: none; font-weight: 500; font-size: 14px; }
        .btn:hover { background: #4752c4; }
        .btn-danger { background: #ef4444; }
        .btn-danger:hover { background: #dc2626; }
        .empty { text-align: center; padding: 60px; color: #6b7280; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div>
            <h1>Admin Panel</h1>
            <p class="subtitle">SevnHub • Registered Users</p>
          </div>
          <div style="display:flex;gap:12px;">
            <a href="/dashboard" class="btn">Back to Site</a>
            <a href="/logout" class="btn btn-danger">Logout</a>
          </div>
        </div>

        <div class="stats">
          <div class="stat">
            <div class="stat-value">${users.length}</div>
            <div class="stat-label">Total Users</div>
          </div>
          <div class="stat">
            <div class="stat-value">${users.filter(u => u.email).length}</div>
            <div class="stat-label">With Email</div>
          </div>
          <div class="stat">
            <div class="stat-value">${users.filter(u => Date.now() - new Date(u.joinedAt) < 86400000).length}</div>
            <div class="stat-label">Joined Today</div>
          </div>
        </div>

        ${users.length === 0 
          ? `<div class="empty">No users registered yet.</div>` 
          : `
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>User</th>
                <th>Username</th>
                <th>Discord ID</th>
                <th>Email</th>
                <th>Joined</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        `}
      </div>
    </body>
    </html>
  `);
});

// Delete user
router.post('/delete/:id', requireAdmin, (req, res) => {
  const users = getUsers();
  const filtered = users.filter(u => u.id !== req.params.id);
  saveUsers(filtered);
  res.redirect('/admin');
});

// Export
module.exports = {
  router,
  getUsers,
  saveUsers,
  addUser: (userData) => {
    const users = getUsers();
    const exists = users.find(u => u.id === userData.id);

    if (!exists) {
      users.push({
        ...userData,
        joinedAt: new Date().toISOString()
      });
    } else {
      const index = users.findIndex(u => u.id === userData.id);
      users[index] = {
        ...users[index],
        ...userData,
        joinedAt: users[index].joinedAt
      };
    }
    saveUsers(users);
  }
};