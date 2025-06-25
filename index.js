require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const writeupsRouter = require('./routes/writeups');





const app = express();

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect()
  .then(() => console.log("✅ Connected to Supabase PostgreSQL"))
  .catch(err => console.error("❌ Connection to DB failed:", err));

// Middleware

const allowedOrigins = [
  'http://localhost:5173',
  'https://the-evanescent.netlify.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

// ✅ Handle preflight OPTIONS requests
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// Routes
app.use('/api/writeups', writeupsRouter(pool, authenticateToken));

// AUTH ROUTES

app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    if (err.code === '23505') {
      res.status(400).json({ error: "Email already exists." });
    } else {
      console.error(err);
      res.status(500).json({ error: "Server error." });
    }
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid credentials." });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials." });

    const accessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

app.post('/api/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid refresh token' });

    const accessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
  });
});




app.post('/api/logout', (req, res) => {
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
});

app.get("/api/health", (req, res) => {
  res.send("Server is running.");
});

app.get('/api/user-info', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userResult = await pool.query("SELECT name, email FROM users WHERE id = $1", [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userResult.rows[0];

    const postCountResult = await pool.query("SELECT COUNT(*) FROM writeups WHERE user_id = $1", [userId]);
    const postCount = parseInt(postCountResult.rows[0].count, 10);

    const totalLikesResult = await pool.query("SELECT COALESCE(SUM(likes), 0) AS totallikes FROM writeups WHERE user_id = $1", [userId]);
    const totalLikes = parseInt(totalLikesResult.rows[0].totallikes, 10);

    res.json({ name: user.name, email: user.email, postCount, totalLikes });

  } catch (err) {
    console.error("Error fetching user info:", err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



  // Claim a bottle
app.post('/api/writeups/claim/:id', authenticateToken, async (req, res) => {
  const writeupId = req.params.id;
  const userId = req.user.id;
  try {
    const result = await pool.query("SELECT * FROM writeups WHERE id = $1", [writeupId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Bottle Empty' });

    if (result.rows[0].claimed_by) {
      return res.status(400).json({ error: 'Already claimed by someone else.' });
    }

    await pool.query("UPDATE writeups SET claimed_by = $1 WHERE id = $2", [userId, writeupId]);
    res.json({ message: 'Bottle claimed successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 🟢 ADD SERVER LISTENING BLOCK (this was your issue earlier)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
