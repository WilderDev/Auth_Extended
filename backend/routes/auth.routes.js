// IMPORTS
const express = require('express');
const router = express.Router();
const { authenticateUser } = require('../middleware/auth');

// CONTROLLERS
const {
  register,
  login,
  verifyEmail,
  me,
  logout,
  forgotPassword,
  resetPassword,
} = require('../controllers/auth');

// ROUTES
router.get('/me', authenticateUser, me);
router.post('/register', register);
router.post('/login', login);
router.post('/verify', verifyEmail);
router.delete('/logout', authenticateUser, logout);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

// EXPORTS
module.exports = router;
