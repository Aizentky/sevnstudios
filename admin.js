const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const MAINTENANCE_FILE = path.join(__dirname, 'data', 'maintenance.json');
const ALLOWED_ADMIN_ID = process.env.ADMIN_DISCORD_ID || '1504098102171406510';

// Ensure data folder + users file exist
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, '[]');
}

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

function getMaintenance() {
  try {
    if (!fs.existsSync(MAINTENANCE_FILE)) return { enabled: false };
    return JSON.parse(fs.readFileSync(MAINTENANCE_FILE, 'utf8'));
  } catch {
    return { enabled: false };
  }
}

function setMaintenance(enabled) {
  fs.writeFileSync(MAINTENANCE_FILE, JSON.stringify({ enabled }, null, 2));
}

// Middleware — only allow your Discord ID
function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  if (req.session.user.id !== ALLOWED_ADMIN_ID) {
    return res.redirect('/dashboard');
  }

  next();
}

// Toggle maintenance mode
router.post('/maintenance', requireAdmin, (req, res) => {
  const current = getMaintenance();
  setMaintenance(!current.enabled);
  res.redirect('/admin');
});

// Delete a user
router.post('/delete/:id', requireAdmin, (req, res) => {
  const users = getUsers().filter(u => u.id !== req.params.id);
  saveUsers(users);
  res.redirect('/admin');
});

// Admin dashboard page
router.get('/', requireAdmin, (req, res) => {
  const users = getUsers();
  const maint = getMaintenance();

  const joinedToday = users.filter(u => {
    if (!u.joinedAt) return false;
    return Date.now() - new Date(u.joinedAt).getTime() < 86400000;
  }).length;

  const rows = users.map((u, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>
        <div style="display:flex;align-items:center;gap:10px;">
          <img
            src="${u.avatar
              ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png`
              : 'https://cdn.discordapp.com/embed/avatars/0.png'}"
            width="32" height="32"
            style="border-radius:8px;object-fit:cover;"
          >
          <div>
            <div style="font-weight:600;">${u.global_name || u.username}</div>
            <div style="font-size:12px;color:#6b7a8f;">@${u.username}</div>
          </div>
        </div>
      </td>
      <td><code>${u.id}</code></td>
      <td>${u.email || '—'}</td>
      <td style="font-size:13px;color:#6b7a8f;">
        ${u.joinedAt ? new Date(u.joinedAt).toLocaleString() : '—'}
      </td>
      <td>
        <form method="POST" action="/admin/delete/${u.id}" style="display:inline;"
              onsubmit="return confirm('Delete this user permanently?')">
          <button type="submit" class="btn-danger">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — SevnHub</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Orbitron:wght@600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #05080a;
      --card: rgba(10, 18, 16, 0.6);
      --border: rgba(0, 255, 156, 0.1);
      --accent: #00ff9c;
      --accent-dim: #00a86b;
      --text: #e6edf3;
      --muted: #6b7a8f;
      --danger: #ff4466;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Outfit', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 40px 24px;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 32px;
      flex-wrap: wrap;
      gap: 16px;
    }
    .header h1 {
      font-family: 'Orbitron', sans-serif;
      font-size: 1.4rem;
      letter-spacing: 0.08em;
      color: var(--accent);
    }
    .header p {
      color: var(--muted);
      font-size: 0.85rem;
      margin-top: 4px;
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    .btn {
      padding: 9px 18px;
      border-radius: 9px;
      font-weight: 600;
      font-size: 0.82rem;
      text-decoration: none;
      border: none;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.2s;
    }
    .btn-outline {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
    }
    .btn-outline:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .btn-maint-on {
      background: rgba(255, 68, 102, 0.15);
      color: var(--danger);
      border: 1px solid rgba(255, 68, 102, 0.3);
    }
    .btn-maint-off {
      background: rgba(0, 255, 156, 0.1);
      color: var(--accent);
      border: 1px solid rgba(0, 255, 156, 0.2);
    }
    .btn-danger {
      background: rgba(255, 68, 102, 0.12);
      color: var(--danger);
      border: 1px solid rgba(255, 68, 102, 0.2);
      padding: 5px 12px;
      border-radius: 7px;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      font-family: inherit;
    }
    .btn-danger:hover {
      background: rgba(255, 68, 102, 0.22);
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .stat {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px 22px;
    }
    .stat-value {
      font-size: 1.8rem;
      font-weight: 800;
      color: var(--accent);
      letter-spacing: -0.03em;
    }
    .stat-label {
      font-size: 0.78rem;
      color: var(--muted);
      margin-top: 4px;
    }
    .panel {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      overflow: hidden;
    }
    .panel-header {
      padding: 18px 22px;
      border-bottom: 1px solid var(--border);
      font-weight: 700;
      font-size: 0.95rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 14px 18px;
      text-align: left;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    th {
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      font-weight: 600;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(0, 255, 156, 0.03); }
    code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: var(--muted);
    }
    .empty {
      text-align: center;
      padding: 48px;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>SEVN ADMIN</h1>
        <p>Manage users & site settings</p>
      </div>
      <div class="actions">
        <form method="POST" action="/admin/maintenance" style="display:inline;">
          <button type="submit" class="btn ${maint.enabled ? 'btn-maint-on' : 'btn-maint-off'}">
            Maintenance: ${maint.enabled ? 'ON' : 'OFF'}
          </button>
        </form>
        <a href="/dashboard" class="btn btn-outline">Dashboard</a>
        <a href="/logout" class="btn btn-outline">Logout</a>
      </div>
    </div>

    <div class="stats">
      <div class="stat">
        <div class="stat-value">${users.length}</div>
        <div class="stat-label">Registered Users</div>
      </div>
      <div class="stat">
        <div class="stat-value">${users.filter(u => u.email).length}</div>
        <div class="stat-label">With Email</div>
      </div>
      <div class="stat">
        <div class="stat-value">${joinedToday}</div>
        <div class="stat-label">Joined Today</div>
      </div>
      <div class="stat">
        <div class="stat-value" style="color:${maint.enabled ? '#ff4466' : '#00ff9c'}">
          ${maint.enabled ? 'ON' : 'OFF'}
        </div>
        <div class="stat-label">Maintenance Mode</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">Members (${users.length})</div>
      ${users.length === 0
        ? '<div class="empty">No users registered yet.</div>'
        : `
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>User</th>
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
  </div>
</body>
</html>
  `);
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
      const i = users.findIndex(u => u.id === userData.id);
      users[i] = {
        ...users[i],
        ...userData,
        joinedAt: users[i].joinedAt
      };
    }

    saveUsers(users);
  }
};
