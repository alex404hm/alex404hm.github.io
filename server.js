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
import asyncHandler from 'express-async-handler';
import winston from 'winston'; // For logging

dotenv.config();

// ======================== Environment Configuration ======================= //

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
  'PORT',
];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    console.error(`❌ Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

// Destructure Environment Variables with Defaults
const {
  BASE_URL = 'http://localhost:3000',
  PORT = process.env.PORT || 3000,
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

// =========================== Logger Setup ============================ //

// Configure winston logger
const logger = winston.createLogger({
  level: NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message} ${
        Object.keys(meta).length ? JSON.stringify(meta) : ''
      }`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'server.log' }),
  ],
});

// ======================== Database Connection ========================== //

mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => logger.info('✅ MongoDB connected successfully'))
  .catch((error) => {
    logger.error('❌ MongoDB connection error:', error);
    process.exit(1);
  });

// ====================== Define Schemas and Models ====================== //

// User Schema
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true }, // Added for user identification
    email: { type: String, required: true, unique: true },
    password: { type: String },
    googleId: { type: String },
    sessionID: { type: String },
    isVerified: { type: Boolean, default: false },
    lastLogin: { type: Date },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    theme: { type: String, default: 'light' }, // User preference
  },
  { timestamps: true }
);

// Ticket Schema
const ticketSchema = new mongoose.Schema(
  {
    subject: { type: String, required: true },
    content: { type: String, required: true },
    status: { type: String, enum: ['open', 'closed'], default: 'open' },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Guide Schema
const guideSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    slug: { type: String, required: true },
    subtitle: String,
    summary: String,
    content: { type: String, required: true },
    tags: [String],
    category: { type: String, required: true },
    bannerImage: String,
    author: {
      id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      name: String,
      email: String,
    },
    publishDate: String,
    views: { type: Number, default: 0 },
  },
  { timestamps: true }
);

// Ensure unique combination of slug and category
guideSchema.index({ slug: 1, category: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);
const Guide = mongoose.model('Guide', guideSchema);
const Ticket = mongoose.model('Ticket', ticketSchema);

// ========================= Utility Functions =========================== //

/**
 * Generate JWT Token
 * @param {Object} user - User object
 * @returns {String} JWT Token
 */
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
      isVerified: user.isVerified,
      name: user.name,
    },
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
    subject: '🔒 Verify Your Email',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Welcome, ${user.name}!</h2>
        <p>Thank you for registering. Please verify your email address to activate your account:</p>
        <a href="${verifyLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
        <p>If you did not sign up for this account, you can ignore this email.</p>
      </div>
    `,
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
    subject: '🎉 Welcome to Our Service!',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Welcome, ${user.name}!</h2>
        <p>We're excited to have you on board. Explore our features and let us know if you have any questions.</p>
        <p>Best Regards,<br/>The Team</p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};

/**
 * Generate a URL-friendly slug from a string
 * @param {String} text - The input text
 * @returns {String} - The generated slug
 */
const generateSlug = (text) => {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '') // Remove non-word characters
    .replace(/[\s_-]+/g, '-') // Replace spaces and underscores with '-'
    .replace(/^-+|-+$/g, ''); // Remove leading and trailing hyphens
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
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${BASE_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
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
        });

        // Send Welcome Email
        await sendWelcomeEmail(user);

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

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
  message: '❌ Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Authentication Rate Limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 requests per windowMs
  message: '❌ Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================== Middleware Setup =========================== //

app.use(generalLimiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true,
  })
);
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(compression());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ====================== Authentication Middleware ====================== //

/**
 * Authenticate JWT Token
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token =
    req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) {
    logger.warn('Unauthorized access attempt.', { url: req.originalUrl });
    return res
      .status(401)
      .json({ error: 'Unauthorized access. Please log in.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) {
      logger.warn('Invalid token provided.', { token });
      return res.status(403).json({ error: 'Forbidden. Invalid token.' });
    }
    req.user = decodedUser;
    next();
  });
};

/**
 * Authenticate Admin Users
 */
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token =
    req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) {
    logger.warn('Admin access denied. No token provided.', {
      url: req.originalUrl,
    });
    return res
      .status(403)
      .json({ error: 'Access Denied: Not Granted Access.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      logger.warn(
        'Admin access denied. Invalid token or insufficient permissions.',
        { token, userRole: decodedUser?.role }
      );
      return res
        .status(403)
        .json({ error: 'Access Denied: Not Granted Access.' });
    }
    req.user = decodedUser;
    next();
  });
};

// =============================== Routes ================================ //

// Define Static Routes with Optional Authentication Redirection
const definedRoutes = [
  {
    route: '/auth/login',
    file: 'auth/login.html',
    redirectIfAuthenticated: true,
  },
  {
    route: '/auth/signup',
    file: 'auth/signup.html',
    redirectIfAuthenticated: true,
  },
  { route: '/', file: 'index.html' },
  {
    route: '/admin/login',
    file: 'admin/login.html',
    redirectIfAuthenticated: true,
  },
];

definedRoutes.forEach(
  ({ route, file, redirectIfAuthenticated: redirectIfAuth }) => {
    if (redirectIfAuth) {
      app.get(
        route,
        (req, res, next) => {
          const authHeader = req.headers.authorization;
          const token =
            req.cookies.token || (authHeader && authHeader.split(' ')[1]);
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
        },
        (req, res) => {
          res.sendFile(path.join(__dirname, 'public', file));
        }
      );
    } else {
      app.get(route, (req, res) => {
        res.sendFile(path.join(__dirname, 'public', file));
      });
    }
  }
);

// Additional Protected Routes
app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(
    path.join(__dirname, 'public', 'dashboard', 'dashboard.html')
  );
});

app.get('/admin', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'admin.html'));
});

// ======================= OAuth Routes ======================= //

// Google OAuth Routes
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
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
app.post(
  '/api/signup',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Input Validation
    if (!name || !email || !password) {
      logger.warn('Signup failed: Missing fields.', { email });
      return res.status(400).json({ error: '❌ All fields are required.' });
    }

    try {
      const existingUser = await User.findOne({ email });

      if (existingUser && existingUser.password) {
        logger.warn('Signup failed: User already exists.', { email });
        return res
          .status(400)
          .json({ error: '❌ User already exists with this email.' });
      }

      const hashedPassword = await bcrypt.hash(
        password,
        parseInt(BCRYPT_SALT_ROUNDS)
      );
      const sessionID = generateSessionID();

      let user;
      if (existingUser) {
        existingUser.password = hashedPassword;
        existingUser.sessionID = sessionID;
        existingUser.name = name; // Update name if provided
        user = await existingUser.save();
      } else {
        user = new User({
          name,
          email,
          password: hashedPassword,
          sessionID,
          role: 'user',
        });
        await user.save();
      }

      const verifyToken = generateToken(user);
      await sendVerificationEmail(user, verifyToken);

      logger.info(`User registered: ${email}`, { userId: user._id });
      res.status(201).json({
        message: '✅ User registered successfully. Please verify your email.',
      });
    } catch (err) {
      if (err.code === 11000) {
        logger.error('Signup error: Duplicate email.', { email });
        res.status(400).json({ error: '❌ Email already in use.' });
      } else {
        logger.error('Signup error:', err);
        res
          .status(500)
          .json({ error: '❌ Server error. Please try again later.' });
      }
    }
  })
);

// Login Endpoint
app.post(
  '/api/login',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Input Validation
    if (!email || !password) {
      logger.warn('Login failed: Missing fields.', { email });
      return res.status(400).json({ error: '❌ All fields are required.' });
    }

    try {
      const user = await User.findOne({ email });

      if (!user || !user.password) {
        logger.warn('Login failed: User does not exist.', { email });
        return res
          .status(404)
          .json({ error: '❌ User does not exist. Please sign up.' });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        logger.warn('Login failed: Invalid credentials.', { email });
        return res.status(401).json({ error: '❌ Invalid credentials.' });
      }

      if (!user.isVerified) {
        logger.warn('Login failed: Email not verified.', { email });
        return res.status(403).json({
          error: '❌ Please verify your email before logging in.',
        });
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

      logger.info(`User logged in: ${email}`, { userId: user._id });
      res.status(200).json({
        message: '✅ Login successful.',
        userInfo: {
          name: user.name,
          email: user.email,
          lastLogin: user.lastLogin,
          isVerified: user.isVerified,
          role: user.role,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
      });
    } catch (err) {
      logger.error('Login error:', err);
      res
        .status(500)
        .json({ error: '❌ Server error. Please try again later.' });
    }
  })
);

// Logout Endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict',
  });
  logger.info(`User logged out: ${req.user.email}`, { userId: req.user.id });
  res.status(200).json({ message: '✅ Logout successful.' });
});

// Verify Email Endpoint
app.get(
  '/api/verify-email',
  asyncHandler(async (req, res) => {
    const token = req.query.token;

    if (!token) {
      return res.status(400).json({ error: '❌ Invalid verification link.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedUser) => {
      if (err) {
        logger.warn('Email verification failed: Invalid token.', { token });
        return res.status(400).json({ error: '❌ Invalid verification link.' });
      }

      try {
        const user = await User.findById(decodedUser.id);

        if (!user) {
          return res.status(404).json({ error: '❌ User not found.' });
        }

        user.isVerified = true;
        await user.save();

        logger.info(`User verified: ${user.email}`, { userId: user._id });
        res.redirect('/auth/login');
      } catch (error) {
        logger.error('Email verification error:', error);
        res
          .status(500)
          .json({ error: '❌ Server error. Please try again later.' });
      }
    });
  })
);

// ========================= Dashboard Endpoint ========================= //

app.get(
  '/api/dashboard-data',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const totalUsers = await User.countDocuments();
      const openTickets = await Ticket.countDocuments({ status: 'open' });
      const closedTickets = await Ticket.countDocuments({ status: 'closed' });
      const recentActivities = []; // Implement your logic to fetch recent activities

      res.json({
        totalUsers,
        openTickets,
        closedTickets,
        recentActivities,
      });
    } catch (error) {
      logger.error('Error fetching dashboard data:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  })
);

// ========================= Users API (Admin) ========================= //

// Get All Users
app.get(
  '/api/users',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const users = await User.find();
      res.json({ users });
    } catch (error) {
      logger.error('Error fetching users:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  })
);

// Create New User
app.post(
  '/api/users',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const { name, email, password, role } = req.body;

      if (!name || !email || !password || !role) {
        return res.status(400).json({ error: '❌ All fields are required.' });
      }

      const hashedPassword = await bcrypt.hash(
        password,
        parseInt(BCRYPT_SALT_ROUNDS)
      );

      const user = new User({
        name,
        email,
        password: hashedPassword,
        role,
        isVerified: true, // Assuming admin is creating verified users
      });

      await user.save();
      logger.info('User created:', { email, userId: user._id });
      res.status(201).json({ message: 'User created successfully.' });
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Error creating user: Email already in use.', { email });
        res.status(400).json({ error: '❌ Email already in use.' });
      } else {
        logger.error('Error creating user:', error);
        res.status(500).json({ error: 'Internal server error.' });
      }
    }
  })
);

// Update User
app.put(
  '/api/users/:id',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const { name, email, password, role } = req.body;
      const updateData = { name, email, role };

      if (password) {
        updateData.password = await bcrypt.hash(
          password,
          parseInt(BCRYPT_SALT_ROUNDS)
        );
      }

      const user = await User.findByIdAndUpdate(req.params.id, updateData, {
        new: true,
      });

      if (!user) {
        logger.warn('User not found for update:', req.params.id);
        return res.status(404).json({ error: 'User not found.' });
      }

      logger.info('User updated:', { email: user.email, userId: user._id });
      res.json({ message: 'User updated successfully.' });
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Error updating user: Email already in use.', {
          email,
          userId: req.params.id,
        });
        res.status(400).json({ error: '❌ Email already in use.' });
      } else {
        logger.error('Error updating user:', error);
        res.status(500).json({ error: 'Internal server error.' });
      }
    }
  })
);

// Deactivate User
app.put(
  '/api/users/:id/deactivate',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const user = await User.findByIdAndUpdate(
        req.params.id,
        { status: 'inactive' },
        { new: true }
      );
      if (!user) {
        logger.warn('User not found for deactivation:', req.params.id);
        return res.status(404).json({ error: 'User not found.' });
      }

      logger.info('User deactivated:', { email: user.email, userId: user._id });
      res.json({ message: 'User deactivated successfully.' });
    } catch (error) {
      logger.error('Error deactivating user:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  })
);

// ========================= Tickets API ========================= //

// Get All Tickets (Admin Only)
app.get(
  '/api/tickets',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const tickets = await Ticket.find().populate('user', 'name email');
      res.json({ tickets });
    } catch (error) {
      logger.error('Error fetching tickets:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  })
);

// Create New Ticket
app.post(
  '/api/tickets',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const { subject, content } = req.body;
      if (!subject || !content) {
        return res.status(400).json({ error: '❌ All fields are required.' });
      }

      const ticket = new Ticket({
        subject,
        content,
        user: req.user.id,
      });

      await ticket.save();
      logger.info('Ticket created:', { ticketId: ticket._id, userId: req.user.id });
      res.status(201).json({ message: 'Ticket created successfully.' });
    } catch (error) {
      logger.error('Error creating ticket:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  })
);

// Close Ticket
app.put(
  '/api/tickets/:id/close',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const ticket = await Ticket.findByIdAndUpdate(
        req.params.id,
        { status: 'closed' },
        { new: true }
      );
      if (!ticket) {
        logger.warn('Ticket not found for closing:', req.params.id);
        return res.status(404).json({ error: 'Ticket not found.' });
      }

      logger.info('Ticket closed:', { ticketId: ticket._id });
      res.json({ message: 'Ticket closed successfully.' });
    } catch (error) {
      logger.error('Error closing ticket:', error);
      res.status(500).json({ error: 'Internal server error.' });
    }
  })
);

// ========================= Guide Endpoints ========================= //

/**
 * Get popular guides sorted by views.
 */
app.get(
  '/api/guides/popular',
  asyncHandler(async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 6;
      const popularGuides = await Guide.find().sort({ views: -1 }).limit(limit);
      res.json({ guides: popularGuides });
    } catch (error) {
      logger.error('Error fetching popular guides:', error);
      res.status(500).json({ error: 'Error fetching popular guides.' });
    }
  })
);

/**
 * Fetch a guide by category and slug.
 */
app.get(
  '/api/guides/:category/:slug',
  asyncHandler(async (req, res) => {
    try {
      const { category, slug } = req.params;
      const guide = await Guide.findOne({
        category: new RegExp(`^${category}$`, 'i'),
        slug: new RegExp(`^${slug}$`, 'i'),
      });
      if (!guide) {
        return res.status(404).json({ error: 'Guide not found.' });
      }
      res.json(guide);
    } catch (error) {
      logger.error('Error fetching guide by category and slug:', {
        error,
        params: req.params,
      });
      res.status(500).json({ error: 'Internal Server Error' });
    }
  })
);

/**
 * Fetch a single guide by ID.
 */
app.get(
  '/api/guides/id/:id',
  asyncHandler(async (req, res) => {
    try {
      const guide = await Guide.findById(req.params.id);
      if (!guide) {
        return res.status(404).json({ error: 'Guide not found.' });
      }
      res.json(guide);
    } catch (error) {
      logger.error('Error fetching guide:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  })
);

/**
 * Fetch all guides, with optional filtering by category, tag, or search.
 */
app.get(
  '/api/guides',
  asyncHandler(async (req, res) => {
    try {
      const { category, tag, search } = req.query;
      let query = {};

      if (category) query.category = new RegExp(category, 'i');
      if (tag) query.tags = new RegExp(tag, 'i');
      if (search)
        query.$or = [
          { title: new RegExp(search, 'i') },
          { summary: new RegExp(search, 'i') },
          { content: new RegExp(search, 'i') },
        ];

      const guides = await Guide.find(query);
      res.json({ guides });
    } catch (error) {
      logger.error('Error fetching guides:', error);
      res.status(500).json({ error: 'Error fetching guides.' });
    }
  })
);

/**
 * Create a new guide.
 */
app.post(
  '/api/guides',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      logger.debug('Received request body:', req.body);
      const { title, subtitle, summary, content, tags, category, bannerImage } =
        req.body;

      // Basic validation checks
      if (!title || typeof title !== 'string') {
        return res
          .status(400)
          .json({ error: 'Title must be a non-empty string.' });
      }
      if (!content || typeof content !== 'string') {
        return res
          .status(400)
          .json({ error: 'Content must be a non-empty string.' });
      }
      if (!category || typeof category !== 'string') {
        return res
          .status(400)
          .json({ error: 'Category must be a valid non-empty string.' });
      }

      const slug = generateSlug(title);

      const newGuide = new Guide({
        title,
        slug,
        subtitle: subtitle || '',
        summary: summary || '',
        content,
        tags: Array.isArray(tags) ? tags : [],
        category,
        bannerImage: bannerImage || '',
        author: {
          id: req.user.id,
          name: req.user.name,
          email: req.user.email,
        },
        publishDate: new Date().toLocaleDateString(),
      });

      const savedGuide = await newGuide.save();
      logger.info(`Guide created: ${title} by ${req.user.email}`, {
        guideId: savedGuide._id,
        userId: req.user.id,
      });
      res.status(201).json(savedGuide);
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Duplicate key error:', { error, body: req.body });
        res.status(400).json({
          error: 'A guide with the same title and category already exists.',
        });
      } else {
        logger.error('Error creating guide:', { error, body: req.body });
        res.status(500).json({ error: 'Error creating guide.' });
      }
    }
  })
);

/**
 * Update an existing guide.
 */
app.put(
  '/api/guides/id/:id',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      logger.debug('Received update request body:', req.body);
      const { title, content, category } = req.body;

      // Optional validation checks before updating
      if (title && typeof title !== 'string') {
        return res
          .status(400)
          .json({ error: 'Title must be a non-empty string.' });
      }
      if (content && typeof content !== 'string') {
        return res
          .status(400)
          .json({ error: 'Content must be a non-empty string.' });
      }
      if (category && typeof category !== 'string') {
        return res
          .status(400)
          .json({ error: 'Category must be a valid non-empty string.' });
      }

      const updates = { ...req.body };
      if (title) {
        updates.slug = generateSlug(title);
      }

      const updatedGuide = await Guide.findByIdAndUpdate(
        req.params.id,
        updates,
        { new: true, runValidators: true }
      );
      if (!updatedGuide) {
        return res.status(404).json({ error: 'Guide not found.' });
      }
      logger.info(`Guide updated: ${updatedGuide.title} by ${req.user.email}`, {
        guideId: updatedGuide._id,
        userId: req.user.id,
      });
      res.json(updatedGuide);
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Duplicate key error:', { error, body: req.body });
        res.status(400).json({
          error: 'A guide with the same title and category already exists.',
        });
      } else {
        logger.error('Error updating guide:', { error, body: req.body });
        res.status(500).json({ error: 'Error updating guide.' });
      }
    }
  })
);

/**
 * Delete a guide by ID.
 */
app.delete(
  '/api/guides/id/:id',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const deletedGuide = await Guide.findByIdAndDelete(req.params.id);
      if (!deletedGuide) {
        return res.status(404).json({ error: 'Guide not found.' });
      }
      logger.info(`Guide deleted: ${deletedGuide.title} by ${req.user.email}`, {
        guideId: deletedGuide._id,
        userId: req.user.id,
      });
      res.json({ message: 'Guide deleted successfully.' });
    } catch (error) {
      logger.error('Error deleting guide:', error);
      res.status(500).json({ error: 'Error deleting guide.' });
    }
  })
);

// ==================== Serve Guide Template ====================== //

/**
 * Serve the guide based on category and slug.
 */
app.get(
  '/articles/:category/:slug',
  asyncHandler(async (req, res) => {
    const { category, slug } = req.params;

    try {
      const guide = await Guide.findOne({
        category: new RegExp(`^${category}$`, 'i'),
        slug: new RegExp(`^${slug}$`, 'i'),
      });

      if (!guide) {
        return res
          .status(404)
          .sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }

      // Serve the template.html file
      res.sendFile(path.join(__dirname, 'public', 'template.html'));
    } catch (error) {
      logger.error('Error fetching guide by category and slug:', {
        error,
        params: req.params,
      });
      res
        .status(500)
        .sendFile(path.join(__dirname, 'public', 'error', '500.html'));
    }
  })
);

// ========================== Error Handling ============================= //

// 404 Handler for API Routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error Handler for API Routes
app.use('/api', (err, req, res, next) => {
  logger.error('❌ API Server Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 Handler for Non-API Routes
app.use((req, res) => {
  res
    .status(404)
    .sendFile(path.join(__dirname, 'public', 'error', '404.html'));
});

// General Error Handler for Non-API Routes
app.use((err, req, res, next) => {
  logger.error('❌ Server Error:', err.stack);
  res
    .status(500)
    .sendFile(path.join(__dirname, 'public', 'error', '500.html'));
});

// =========================== Start Server ============================== //

app.listen(PORT, () => {
  logger.info(`🚀 Server is running on port ${PORT}`);
});