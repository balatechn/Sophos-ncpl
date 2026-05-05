const express = require('express');
const router = express.Router();

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const validUser = process.env.DASHBOARD_USERNAME || 'admin';
  const validPass = process.env.DASHBOARD_PASSWORD || 'admin';

  if (username === validUser && password === validPass) {
    req.session.user = { username };
    return res.redirect('/');
  }

  req.flash('error', 'Invalid username or password');
  return res.redirect('/login?error=1');
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

module.exports = router;
