const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const authMiddleware = {
    
    verifyToken: (req, res, next) => {
        const token = req.cookies.token;
        if (!token) return res.redirect('/login?error=Please login');
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        } catch (err) {
            res.redirect('/login?error=Invalid or expired token');
        }
    },

    
    loginLimiter: rateLimit({
        windowMs: 15 * 60 * 1000, 
        max: 5, 
        message: 'Too many login attempts, please try again after 15 minutes'
    })
};

module.exports = authMiddleware;