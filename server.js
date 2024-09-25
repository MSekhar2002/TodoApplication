const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();
const app = express();
var cors = require('cors')
app.use(cors())
// Database setup
app.get( '/' ,(req, res) => res.send( 'Success'));
const db = new sqlite3.Database('./todoApp.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to SQLite database.');
});

// Create users and tasks table if they don't exist
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT,
    status TEXT,
    user_id TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )
`);

app.use(express.json());

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret';

// Middleware to authenticate users
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// User Signup
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const id = uuidv4();

  db.run('INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)', [id, name, email, hashedPassword], (err) => {
    if (err) return res.status(400).json({ error: 'Email already exists' });

    const token = jwt.sign({ id, name, email }, JWT_SECRET);
    res.json({ token });
  });
});

// User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET);
    res.json({ token });
  });
});

// Fetch user profile
app.get('/profile', authenticateToken, (req, res) => {
  db.get('SELECT id, name, email FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch user profile' });
    res.json(user);
  });
});

// Update user profile
app.patch('/profile', authenticateToken, (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = password ? bcrypt.hashSync(password, 10) : undefined;

  db.run(
    `UPDATE users SET name = ?, email = ?, password = COALESCE(?, password) WHERE id = ?`,
    [name, email, hashedPassword, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to update profile' });
      res.json({ message: 'Profile updated successfully' });
    }
  );
});

// Create new task
app.post('/tasks', authenticateToken, (req, res) => {
  const { title, status } = req.body;
  const id = uuidv4();

  db.run('INSERT INTO tasks (id, title, status, user_id) VALUES (?, ?, ?, ?)', [id, title, status, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to create task' });
    res.json({ id, title, status });
  });
});

// Get all tasks for the authenticated user
app.get('/tasks', authenticateToken, (req, res) => {
  db.all('SELECT * FROM tasks WHERE user_id = ?', [req.user.id], (err, tasks) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch tasks' });
    res.json(tasks);
  });
});

// Update task status
app.patch('/tasks/:id', authenticateToken, (req, res) => {
  const { status } = req.body;
  const { id } = req.params;

  db.run('UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?', [status, id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update task' });
    res.json({ message: 'Task updated successfully' });
  });
});

// Delete task
app.delete('/tasks/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  db.run('DELETE FROM tasks WHERE id = ? AND user_id = ?', [id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to delete task' });
    res.json({ message: 'Task deleted successfully' });
  });
});

module.exports = app;

