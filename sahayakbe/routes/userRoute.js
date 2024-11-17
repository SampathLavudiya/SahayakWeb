const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/userSchema');
const cookieParser = require('cookie-parser');
const router = express.Router();

// Use cookie-parser middleware
router.use(cookieParser());

// Signup Route
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error registering user' });
  }
});

// Login Route with Cookie
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() }); // Case insensitive email lookup
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Send JWT in an HttpOnly, Secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',  // Set to true in production for secure cookies
      maxAge: 3600000  // 1 hour expiry time for the cookie
    });

    res.json({ message: 'Login successful' });

  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ error: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Store the decoded user ID in the request object
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Example of a protected route
router.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'You have access to this protected route', userId: req.user.userId });
});

router.post('/logout', (req, res) => {
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    res.json({ message: 'Logged out successfully' });
  });
  
  router.get('/info', verifyToken, async (req, res) => {
    try {
      const user = await User.findById(req.user.userId);
      res.json({ username: user.username });
    } catch (error) {
      res.status(500).json({ error: 'Unable to fetch user information' });
    }
  });


  
  

module.exports = router;
