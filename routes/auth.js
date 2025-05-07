const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const pool = require('../utils/db');
const router = express.Router();

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login?error=Please login');
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.redirect('/login?error=Invalid or expired token');
    }
};


const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: 'Too many login attempts, please try again after 15 minutes'
});

router.get('/register', (req, res) => {
    console.log('Rendering register page');
    res.render('register', { error: req.query.error });
});

router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    console.log('Register attempt:', { username, email });
    
    if (!username || !email || !password) {
        return res.redirect('/register?error=All fields are required');
    }
    
    if (password.length < 8) {
        return res.redirect('/register?error=Password must be at least 8 characters');
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.redirect('/register?error=Invalid email format');
    }
    
    try {
        console.log('Checking for existing user');
        const userCheck = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );
        
        if (userCheck.rows.length > 0) {
            return res.redirect('/register?error=Username or email already exists');
        }
        
        console.log('Hashing password');
        const hashedPassword = await bcrypt.hash(password, 10);
        
        console.log('Inserting user into database');
        await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
            [username, email, hashedPassword]
        );
        
        res.redirect('/login?success=Registration successful, please login');
    } catch (err) {
        console.error('Registration error:', err);
        res.redirect('/register?error=Server error');
    }
});

router.get('/login', (req, res) => {
    res.render('login', { 
        error: req.query.error,
        success: req.query.success,
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY
    });
});

router.post('/login', loginLimiter, async (req, res) => {
    const { username, password, 'g-recaptcha-response': recaptchaResponse } = req.body;
    
    if (!username || !password || !recaptchaResponse) {
        return res.redirect('/login?error=All fields are required');
    }
    
    try {
        const recaptchaVerification = await axios.post(
            'https://www.google.com/recaptcha/api/siteverify',
            null,
            {
                params: {
                    secret: process.env.RECAPTCHA_SECRET_KEY,
                    response: recaptchaResponse
                }
            }
        );
        
        if (!recaptchaVerification.data.success) {
            return res.redirect('/login?error=Invalid reCAPTCHA');
        }
        
        const user = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [username]
        );
        
        if (user.rows.length === 0) {
            return res.redirect('/login?error=Invalid credentials');
        }
        
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            return res.redirect('/login?error=Invalid credentials');
        }
        
        const token = jwt.sign(
            {
                id: user.rows[0].id,
                username: user.rows[0].username,
                email: user.rows[0].email
            },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );
        
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/profile');
    } catch (err) {
        console.error('Login error:', err);
        res.redirect('/login?error=Server error');
    }
});

router.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await pool.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [req.user.id]);
        res.render('profile', { user: user.rows[0] });
    } catch (err) {
        console.error('Profile error:', err);
        res.redirect('/login?error=Server error');
    }
});

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

module.exports = router;