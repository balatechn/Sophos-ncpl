require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const flash = require('connect-flash');
const rateLimit = require('express-rate-limit');
const path = require('path');

const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const { requireAuth } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers (relaxed CSP for inline Tailwind/Alpine)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
      fontSrc: ["'self'", "fonts.gstatic.com", "cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: null,
    },
  },
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,  // set true behind HTTPS proxy
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000  // 8 hours
  }
}));

app.use(flash());

// Rate limit login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Pass flash messages to all views
app.use((req, res, next) => {
  res.locals.flashError = req.flash('error');
  res.locals.user = req.session.user || null;
  next();
});

app.set('view engine', 'html');

// Routes
app.use('/auth', loginLimiter, authRoutes);
app.use('/api', requireAuth, apiRoutes);

// Pages
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

app.get('/endpoints', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/endpoints.html'));
});

app.get('/alerts', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/alerts.html'));
});

app.get('/admins', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admins.html'));
});

app.get('/threats', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/threats.html'));
});

app.listen(PORT, () => {
  console.log(`Sophos Dashboard running on port ${PORT}`);
});
