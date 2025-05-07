const express = require('express');
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const router = express.Router();


router.get('/register', authController.getRegister);
router.post('/register', authController.postRegister);
router.get('/login', authController.getLogin);
router.post('/login', authMiddleware.loginLimiter, authController.postLogin);
router.get('/profile', authMiddleware.verifyToken, authController.getProfile);
router.get('/logout', authController.getLogout);

module.exports = router;