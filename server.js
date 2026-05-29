const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-please-change-in-production';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
ensureDir(DATA_DIR);
ensureDir(path.join(DATA_DIR, 'planner'));

// ─── FILE HELPERS ───

function readJSON(filePath, fallback) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { return fallback; }
}
function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function readUsers() { return readJSON(USERS_FILE, []); }
function writeUsers(u) { writeJSON(USERS_FILE, u); }

function userDir(userId) {
  const p = path.join(DATA_DIR, 'planner', String(userId));
  ensureDir(p);
  return p;
}
function plannerPath(userId, date) { return path.join(userDir(userId), `${date}.json`); }
function projectsPath(userId) { return path.join(userDir(userId), 'projects.json'); }
function notesPath(userId) { return path.join(userDir(userId), 'notes.json'); }

function readPlanner(userId, date) { return readJSON(plannerPath(userId, date), null); }
function writePlanner(userId, date, data) { writeJSON(plannerPath(userId, date), data); }
function readProjects(userId) { return readJSON(projectsPath(userId), []); }
function writeProjects(userId, data) { writeJSON(projectsPath(userId), data); }
function readNotes(userId) { return readJSON(notesPath(userId), []); }
function writeNotes(userId, data) { writeJSON(notesPath(userId), data); }

// ─── MIDDLEWARE ───

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login.html');
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.clearCookie('token'); res.redirect('/login.html'); }
}

function requireAuthAPI(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.clearCookie('token'); res.status(401).json({ error: 'Invalid token' }); }
}

// ─── AUTH ───

app.post('/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (username.trim().length < 2) return res.status(400).json({ error: 'Username must be at least 2 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const users = readUsers();
  const emailLower = email.trim().toLowerCase();
  const usernameTrim = username.trim();
  if (users.find(u => u.email === emailLower)) return res.status(400).json({ error: 'Email already taken' });
  if (users.find(u => u.username.toLowerCase() === usernameTrim.toLowerCase()))
    return res.status(400).json({ error: 'Username already taken' });

  const newUser = { id: Date.now(), username: usernameTrim, email: emailLower, passwordHash: bcrypt.hashSync(password, 12), createdAt: new Date().toISOString() };
  users.push(newUser);
  writeUsers(users);
  const token = jwt.sign({ id: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const users = readUsers();
  const user = users.find(u => u.email === email.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true });
});

app.post('/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ success: true }); });
app.get('/auth/me', requireAuthAPI, (req, res) => res.json({ username: req.user.username, id: req.user.id }));

// ─── PLANNER DATA ───

const EMPTY_DAY = { blocks: [], nextId: 1, objectives: '', dailyGiven: '', brainDump: '', tasks: [], meetings: [], dayBoxes: null, currentFocus: '', dailyLog: '' };

app.get('/api/data/:date', requireAuthAPI, (req, res) => {
  res.json(readPlanner(req.user.id, req.params.date) || { ...EMPTY_DAY });
});

app.post('/api/data/:date', requireAuthAPI, (req, res) => {
  const { blocks, nextId, objectives, dailyGiven, brainDump, tasks, meetings, dayBoxes, currentFocus, dailyLog } = req.body;
  writePlanner(req.user.id, req.params.date, {
    blocks: blocks || [], nextId: nextId || 1, objectives: objectives || '',
    dailyGiven: dailyGiven || '', brainDump: brainDump || '',
    tasks: tasks || [], meetings: meetings || [], dayBoxes: Array.isArray(dayBoxes) ? dayBoxes : null,
    currentFocus: currentFocus || '', dailyLog: dailyLog || '',
    updatedAt: new Date().toISOString(),
  });
  res.json({ success: true });
});

app.get('/api/history', requireAuthAPI, (req, res) => {
  const dir = userDir(req.user.id);
  try {
    const dates = fs.readdirSync(dir)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.json$/.test(f))
      .map(f => f.replace('.json', ''))
      .sort().reverse();
    res.json({ dates });
  } catch { res.json({ dates: [] }); }
});

// ─── PROJECTS ───

app.get('/api/projects', requireAuthAPI, (req, res) => res.json({ projects: readProjects(req.user.id) }));

app.post('/api/projects', requireAuthAPI, (req, res) => {
  const { name, color, description } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Project name required' });
  const projects = readProjects(req.user.id);
  const ts = Date.now();
  const project = {
    id: `proj_${ts}`,
    name: name.trim(),
    color: color || '#d4a853',
    description: description || '',
    columns: [
      { id: `col_${ts}_1`, title: 'BACKLOG', cards: [] },
      { id: `col_${ts}_2`, title: 'IN PROGRESS', cards: [] },
      { id: `col_${ts}_3`, title: 'REVIEW', cards: [] },
      { id: `col_${ts}_4`, title: 'DONE', cards: [] },
    ],
    timelineBlocks: [],
    createdAt: new Date().toISOString(),
  };
  projects.push(project);
  writeProjects(req.user.id, projects);
  res.json({ project });
});

app.put('/api/projects/:id', requireAuthAPI, (req, res) => {
  const projects = readProjects(req.user.id);
  const idx = projects.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  projects[idx] = { ...req.body, id: req.params.id, updatedAt: new Date().toISOString() };
  writeProjects(req.user.id, projects);
  res.json({ success: true });
});

app.delete('/api/projects/:id', requireAuthAPI, (req, res) => {
  writeProjects(req.user.id, readProjects(req.user.id).filter(p => p.id !== req.params.id));
  res.json({ success: true });
});

// ─── NOTES ───

app.get('/api/notes', requireAuthAPI, (req, res) => res.json({ notes: readNotes(req.user.id) }));

app.post('/api/notes', requireAuthAPI, (req, res) => {
  const notes = readNotes(req.user.id);
  const note = {
    id: `note_${Date.now()}`,
    title: req.body.title || 'Untitled',
    content: req.body.content || '',
    tags: req.body.tags || [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  notes.unshift(note);
  writeNotes(req.user.id, notes);
  res.json({ note });
});

app.put('/api/notes/:id', requireAuthAPI, (req, res) => {
  const notes = readNotes(req.user.id);
  const idx = notes.findIndex(n => n.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  notes[idx] = { ...notes[idx], ...req.body, id: req.params.id, updatedAt: new Date().toISOString() };
  writeNotes(req.user.id, notes);
  res.json({ success: true });
});

app.delete('/api/notes/:id', requireAuthAPI, (req, res) => {
  writeNotes(req.user.id, readNotes(req.user.id).filter(n => n.id !== req.params.id));
  res.json({ success: true });
});

// ─── SERVE APP ───

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));
app.get('/app', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`Mind Mine running on port ${PORT}`));
