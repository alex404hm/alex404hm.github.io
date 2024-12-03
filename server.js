// server.js

// ============================ Module Imports ============================ //

import express from 'express';
import path from 'path';
import cors from 'cors';
import morgan from 'morgan';
import compression from 'compression';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'url';
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { v4 as uuidv4 } from 'uuid';
import asyncHandler from 'express-async-handler';

// ======================== Environment Configuration ======================= //

// Load Environment Variables
dotenv.config();

// Validate Required Environment Variables
const requiredEnvVars = [
  'BASE_URL',
  'MONGODB_URI',
  'JWT_SECRET',
  'EMAIL_USER',
  'EMAIL_APP_PASSWORD',
  'SESSION_SECRET',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'CORS_ORIGIN',
  'PORT'
];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    console.error(`\u274C Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

// Destructure Environment Variables with Defaults
const {
  BASE_URL = 'http://localhost:3000',
  PORT = 3000,
  NODE_ENV = 'development',
  JWT_EXPIRES_IN = '1h',
  CORS_ORIGIN,
  BCRYPT_SALT_ROUNDS = '10',
} = process.env;

// =========================== Initialize App ============================ //

const app = express();

// Determine __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ======================== Database Connection ========================== //

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('\u2705 MongoDB connected successfully'))
.catch((error) => {
  console.error('\u274C MongoDB connection error:', error);
  process.exit(1);
});

// ====================== Define Schemas and Models ====================== //

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true }, // Added for user identification
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String },
  sessionID: { type: String },
  isVerified: { type: Boolean, default: false },
  lastLogin: { type: Date },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  theme: { type: String, default: 'light' }, // User preference
}, { timestamps: true });

// Ticket Schema
const ticketSchema = new mongoose.Schema({
  user: { type: String, required: true }, // Assuming user's email or name
  subject: { type: String, required: true },
  status: { type: String, enum: ['open', 'closed'], default: 'open' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  description: { type: String, default: '' },
  timestamp: { type: Date, default: Date.now },
}, { timestamps: true });

// Visit Schema
const visitSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  page: { type: String, required: true },
}, { timestamps: true });

// Chat Schema
const chatSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String },
  sender: { type: String },
  status: { type: String },
}, { timestamps: true });

// Feedback Schema
const feedbackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  feedback: { type: String, required: true },
}, { timestamps: true });

// Guide Schema
const guideSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, required: true },
  banner: { type: String, default: '' },
  tags: { type: String, default: '' },
  youtubeLink: { type: String, default: '' },
  shares: { type: Number, default: 0 },
  saved: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Ticket = mongoose.model('Ticket', ticketSchema);
const Visit = mongoose.model('Visit', visitSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Feedback = mongoose.model('Feedback', feedbackSchema);
const Guide = mongoose.model('Guide', guideSchema);

// ========================= Utility Functions =========================== //

/**
 * Generate JWT Token
 * @param {Object} user - User object
 * @returns {String} JWT Token
 */
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role, isVerified: user.isVerified }, // Include isVerified
    process.env.JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
};

/**
 * Generate a random Session ID
 * @returns {String} Session ID
 */
const generateSessionID = () => crypto.randomBytes(16).toString('hex');

/**
 * Send Verification Email
 * @param {Object} user - User object
 * @param {String} token - JWT Token
 */
const sendVerificationEmail = async (user, token) => {
  const verifyLink = `${BASE_URL}/api/verify-email?token=${token}`;

  const mailOptions = {
    from: `"No Reply" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: '\uD83D\uDD12 Verify Your Email',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Welcome, ${user.name}!</h2>
        <p>Thank you for registering. Please verify your email address to activate your account:</p>
        <a href="${verifyLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
        <p>If you did not sign up for this account, you can ignore this email.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

/**
 * Send Welcome Email
 * @param {Object} user - User object
 */
const sendWelcomeEmail = async (user) => {
  const mailOptions = {
    from: `"No Reply" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: '\uD83C\uDF89 Welcome to Our Service!',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Welcome, ${user.name}!</h2>
        <p>We're excited to have you on board. Explore our features and let us know if you have any questions.</p>
        <p>Best Regards,<br/>The Team</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

// ======================== Nodemailer Configuration ====================== //

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

// ====================== Passport Configuration ========================== //

// Passport Configuration for Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Extract email
    const email = profile.emails[0].value;

    // Check if user with this email already exists
    let user = await User.findOne({ email });

    if (user) {
      // If user exists but doesn't have Google ID, link it
      if (!user.googleId) {
        user.googleId = profile.id;
        await user.save();
      }
      return done(null, user);
    }

    // If user doesn't exist, create new
    user = await User.create({
      googleId: profile.id,
      name: profile.displayName,
      email: email,
      isVerified: true, // Google OAuth provides verified email
      role: 'user',
      description: 'Created a new user via Google OAuth.'
    });

    // Send Welcome Email
    await sendWelcomeEmail(user);

    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// =========================== Rate Limiting ============================ //

// General API Rate Limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
  message: '\u274C Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Authentication Rate Limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 requests per windowMs
  message: '\u274C Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================== Middleware Setup =========================== //

app.use(generalLimiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: CORS_ORIGIN,
  credentials: true,
}));
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(compression());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  },
}));
app.use(passport.initialize());
app.use(passport.session());

// ====================== Authentication Middleware ====================== //

/**
 * Authenticate JWT Token
 */
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) {
    return res.redirect('/auth/login');
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.redirect('/auth/login');
    }
    req.user = decodedUser;
    next();
  });
};

/**
 * Redirect if User is Already Authenticated
 */
const redirectIfAuthenticatedMiddleware = (req, res, next) => {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err) => {
      if (!err) {
        return res.redirect('/dashboard');
      }
      next();
    });
  } else {
    next();
  }
};

/**
 * Authenticate Admin Users
 */
const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) {
    return res.status(403).send('Access Denied: Not Granted Access.');
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      return res.status(403).send('Access Denied: Not Granted Access.');
    }
    req.user = decodedUser;
    next();
  });
};

// =============================== Routes ================================ //

// Define Static Routes with Optional Authentication Redirection
const definedRoutes = [
  { route: '/auth/login', file: 'auth/login.html', redirectIfAuthenticated: true },
  { route: '/auth/signup', file: 'auth/signup.html', redirectIfAuthenticated: true },
  { route: '/', file: 'index.html' },
  { route: '/admin/login', file: 'admin/login.html', redirectIfAuthenticated: true },
];

definedRoutes.forEach(({ route, file, redirectIfAuthenticated: redirectIfAuth }) => {
  if (redirectIfAuth) {
    app.get(route, redirectIfAuthenticatedMiddleware, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  } else {
    app.get(route, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  }
});

// Additional Protected Routes
app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'dashboard.html'));
});

app.get('/find', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'find.html'));
});

app.get('/profile', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'profile.html'));
});

// ======================= OAuth Routes ======================= //

// Google OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/auth/login' }),
  (req, res) => {
    // Successful authentication, generate JWT token and set cookie
    const token = generateToken(req.user);
    res.cookie('token', token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });
    res.redirect('/dashboard');
  }
);

// ========================= API Endpoints ========================= //

// User Registration Endpoint
app.post('/api/signup', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;

  // Input Validation
  if (!name || !email || !password) {
    return res.status(400).json({ error: '\u274C All fields are required.' });
  }

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.password) {
      return res.status(400).json({ error: '\u274C User already exists with this email.' });
    }

    const hashedPassword = await bcrypt.hash(password, parseInt(BCRYPT_SALT_ROUNDS));
    const sessionID = generateSessionID();

    let user;
    if (existingUser) {
      existingUser.password = hashedPassword;
      existingUser.sessionID = sessionID;
      existingUser.name = name; // Update name if provided
      user = await existingUser.save();
    } else {
      user = new User({ name, email, password: hashedPassword, sessionID, role: 'user' });
      await user.save();

      // Send Welcome Email
      await sendWelcomeEmail(user);
    }

    const verifyToken = generateToken(user);
    await sendVerificationEmail(user, verifyToken);

    res.status(201).json({ message: '\u2705 User registered successfully. Please verify your email.' });
  } catch (err) {
    console.error('\u274C Error creating user:', err);
    res.status(500).json({ error: '\u274C Server error. Please try again later.' });
  }
});

// Send Verification Email Endpoint
app.post('/api/send-verification-email', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ error: '\u274C User not found.' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: '\u2139\uFE0F User is already verified.' });
    }

    const verifyToken = generateToken(user);
    await sendVerificationEmail(user, verifyToken);
    res.status(200).json({ message: '\u2705 Verification email sent successfully.' });
  } catch (error) {
    console.error('\u274C Error sending verification email:', error);
    res.status(500).json({ error: '\u274C Server error. Could not send verification email.' });
  }
});

// Email Verification Endpoint
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).sendFile(path.join(__dirname, 'public', 'error', '400.html'));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
    }

    if (user.isVerified) {
      return res.redirect('/dashboard');
    }

    user.isVerified = true;
    await user.save();

    // Send Welcome Email after verification
    await sendWelcomeEmail(user);

    res.sendFile(path.join(__dirname, 'public', 'auth', 'verified.html'));
  } catch (error) {
    console.error('\u274C Error verifying email:', error);
    res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
  }
});

// Logout Endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.status(200).json({ message: '\u2705 Logout successful.' });
});

// Login Endpoint
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  // Input Validation
  if (!email || !password) {
    return res.status(400).json({ error: '\u274C All fields are required.' });
  }

  try {
    const user = await User.findOne({ email });

    if (!user || !user.password) {
      return res.status(404).json({ error: '\u274C User does not exist. Please sign up.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: '\u274C Invalid credentials.' });
    }

    // Removed the isVerified check to allow login
    // if (!user.isVerified) {
    //   return res.status(403).json({ error: '\u274C Please verify your email before logging in.' });
    // }

    const token = generateToken(user);
    const sessionID = generateSessionID();
    user.sessionID = sessionID;
    user.lastLogin = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.status(200).json({
      message: '\u2705 Login successful.',
      userInfo: {
        name: user.name,
        email: user.email,
        lastLogin: user.lastLogin,
        isVerified: user.isVerified,
        role: user.role,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      }
    });
  } catch (err) {
    console.error('\u274C Error logging in user:', err);
    res.status(500).json({ error: '\u274C Server error. Please try again later.' });
  }
});

// Admin Login Endpoint
app.post('/api/admin/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  // Input Validation
  if (!email || !password) {
    return res.status(400).json({ error: '\u274C All fields are required.' });
  }

  try {
    const user = await User.findOne({ email });

    if (!user || !user.password) {
      return res.status(404).json({ error: '\u274C User does not exist. Please sign up.' });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({ error: '\u274C Access Denied: Not Granted Access.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: '\u274C Invalid credentials.' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ error: '\u274C Please verify your email before logging in.' });
    }

    const token = generateToken(user);
    const sessionID = generateSessionID();
    user.sessionID = sessionID;
    user.lastLogin = new Date();
    await user.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.status(200).json({
      message: '\u2705 Admin login successful.',
      userInfo: {
        name: user.name,
        email: user.email,
        lastLogin: user.lastLogin,
        isVerified: user.isVerified,
        role: user.role,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      }
    });
  } catch (err) {
    console.error('\u274C Error logging in admin:', err);
    res.status(500).json({ error: '\u274C Server error. Please try again later.' });
  }
});

// Admin Protected Route to Access Admin Dashboard
app.get('/admin', authenticateAdmin, asyncHandler(async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user.isVerified) {
      return res.redirect('/verify');
    }

    res.sendFile(path.join(__dirname, 'public', 'admin', 'admin.html'));
  } catch (err) {
    console.error('\u274C Error accessing admin route:', err);
    res.redirect('/admin/login');
  }
}));

// Verification Page Redirect
app.get('/verify', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth', 'verify.html'));
});

// ========================= New API Endpoints ========================= //

// Dashboard Data Endpoint
app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  try {
    // Simulate data fetching delay
    await new Promise(resolve => setTimeout(resolve, 500));

    const totalUsers = await User.countDocuments();
    const openTickets = await Ticket.countDocuments({ status: 'open' });
    const closedTickets = await Ticket.countDocuments({ status: 'closed' });

    const recentUsers = await User.find().sort({ createdAt: -1 }).limit(5);
    const recentTickets = await Ticket.find().sort({ createdAt: -1 }).limit(5);

    const recentActivities = [
      ...recentUsers.map(user => ({
        description: `User ${user.name} registered.`,
        timestamp: user.createdAt,
        type: 'user'
      })),
      ...recentTickets.map(ticket => ({
        description: `Ticket "${ticket.subject}" was created.`,
        timestamp: ticket.createdAt,
        type: 'ticket'
      }))
    ]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 5);

    res.json({ totalUsers, openTickets, closedTickets, recentActivities });
  } catch (error) {
    console.error('\u274C Error fetching dashboard data:', error);
    res.status(500).json({ error: '\u274C Server error. Could not fetch dashboard data.' });
  }
});

// Endpoint to Get User Info (Added)
app.get('/api/user-info', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: '\u274C User not found.' });
    }
    res.status(200).json({ user });
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: '\u274C Server error. Could not fetch user info.' });
  }
});

// Rest of your API endpoints...

// ========================== Error Handling ============================= //

// 404 Error Handling for Unknown Routes
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
});

// General Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('\u274C Server Error:', err.stack);
  res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
});

// =========================== Start Server ============================== //

app.listen(PORT, () => {
  console.log(`\uD83D\uDE80 Server is running on port ${PORT}`);
});