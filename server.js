// ============================ Module Imports ============================ //
import express from 'express';
import path from 'path';
import http from 'http';
import { fileURLToPath } from 'url';
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
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import asyncHandler from 'express-async-handler';
import winston from 'winston';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { body, validationResult } from 'express-validator';
import { Server as SocketIOServer } from 'socket.io';
import Stripe from 'stripe';
import PDFDocument from 'pdfkit';
import fs from 'fs';

// ============================= Configuration ============================== //

dotenv.config();

// Validate Required Environment Variables
const requiredEnvVars = [
  'BASE_URL',
  'PORT',
  'NODE_ENV',
  'MONGODB_URI',
  'JWT_SECRET',
  'EMAIL_USER',
  'EMAIL_APP_PASSWORD',
  'SESSION_SECRET',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'CORS_ORIGIN',
  'BCRYPT_SALT_ROUNDS',
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
];
requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    console.error(`❌ Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

const {
  BASE_URL = 'http://localhost:3000',
  PORT = process.env.PORT || 3000,
  NODE_ENV = 'development',
  JWT_EXPIRES_IN = '1h',
  CORS_ORIGIN,
  BCRYPT_SALT_ROUNDS = '10',
  MONGODB_URI,
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
} = process.env;

// Initialize Stripe
const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: '2024-04-10',
});

// Determine __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================= Logger Setup ============================== //

// Configure Winston Logger
const logger = winston.createLogger({
  level: NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(
      ({ timestamp, level, message, ...meta }) =>
        `${timestamp} [${level.toUpperCase()}]: ${message} ${
          Object.keys(meta).length ? JSON.stringify(meta) : ''
        }`
    )
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/server.log' }),
  ],
});

// =========================== Database Connection ========================= //

mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => logger.info('✅ MongoDB connected successfully'))
  .catch((error) => {
    logger.error('❌ MongoDB connection error:', error);
    process.exit(1);
  });

// =========================== Mongoose Models ============================ //

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
    isPremium: { type: Boolean, default: false },
    phoneNumber: { type: String },
  },
  { timestamps: true }
);

// Response Schema for Tickets
const responseSchema = new mongoose.Schema({
  sender: { type: String, required: true }, // 'User' or 'Support'
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

// Ticket Schema
const ticketSchema = new mongoose.Schema(
  {
    ticketId: { type: String, default: () => uuidv4(), unique: true },
    subject: { type: String, required: true, maxlength: 100 },
    description: { type: String, required: true, maxlength: 1000 },
    imageUrl: { type: String }, // URL to the uploaded image
    status: { type: String, enum: ['open', 'pending', 'closed'], default: 'open' },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    category: { type: String },
    createdDate: { type: Date, default: Date.now },
    responses: [responseSchema],
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
const Ticket = mongoose.model('Ticket', ticketSchema);
const Guide = mongoose.model('Guide', guideSchema);

// ========================= Nodemailer Configuration ====================== //

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

transporter.verify((error, success) => {
  if (error) {
    logger.error('❌ Nodemailer transporter error:', error);
  } else {
    logger.info('✅ Nodemailer transporter is ready to send emails');
  }
});

// ========================= Passport Configuration ========================= //

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

        logger.info(`✅ New user registered via Google: ${email}`, { userId: user._id });
        return done(null, user);
      } catch (err) {
        logger.error('❌ Google OAuth Error:', err);
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

// =========================== Multer Configuration ======================== //

// Multer Configuration for Image Uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'public', 'uploads')); // Ensure this directory exists
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = `${Date.now()}-${uuidv4()}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const fileTypes = /jpeg|jpg|png|gif/;
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = fileTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('❌ Only images are allowed (jpeg, jpg, png, gif).'));
    }
  },
});

// =========================== Helper Functions ============================ //

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
      isPremium: user.isPremium,
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

/**
 * Get Client IP Address
 * @param {Object} req - Express request object
 * @returns {String} IP Address
 */
const getClientIP = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
};

/**
 * Get Geolocation from IP
 * @param {String} ip - IP Address
 * @returns {String} Geolocation
 */
const getGeolocation = async (ip) => {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await response.json();
    if (data.status === 'success') {
      return `${data.city}, ${data.regionName}, ${data.country}`;
    }
    return 'Unknown Location';
  } catch (error) {
    logger.error('❌ Error fetching geolocation:', error);
    return 'Unknown Location';
  }
};

/**
 * Generate PDF Invoice
 * @param {Object} user - User object
 * @param {String} transactionId - Transaction ID from Stripe
 * @returns {Buffer} PDF Buffer
 */
const generateInvoice = (user, transactionId) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument();
      const buffers = [];

      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => {
        const pdfData = Buffer.concat(buffers);
        resolve(pdfData);
      });

      // PDF Content
      doc.fontSize(20).text('Invoice', { align: 'center' });
      doc.moveDown();

      doc.fontSize(12).text(`Invoice To:`, { underline: true });
      doc.text(`Name: ${user.name}`);
      doc.text(`Email: ${user.email}`);
      doc.text(`Phone: ${user.phoneNumber || 'N/A'}`);
      doc.text(`Date: ${new Date().toLocaleDateString()}`);
      doc.text(`Transaction ID: ${transactionId}`);
      doc.moveDown();

      doc.text(`Description: Premium Membership Access`);
      doc.text(`Amount: $50.00`);
      doc.moveDown();

      doc.text('Thank you for your purchase!', { align: 'center' });

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
};

/**
 * Send Invoice Email
 * @param {Object} user - User object
 * @param {String} transactionId - Transaction ID from Stripe
 * @param {Buffer} invoicePDF - PDF Buffer
 */
const sendInvoiceEmail = async (user, transactionId, invoicePDF) => {
  const mailOptions = {
    from: `"No Reply" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: '🧾 Your Premium Membership Invoice',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Thank You for Your Purchase, ${user.name}!</h2>
        <p>Attached is your invoice for the Premium Membership.</p>
        <p>If you have any questions, feel free to contact our support team.</p>
        <p>Best Regards,<br/>The Team</p>
      </div>
    `,
    attachments: [
      {
        filename: 'invoice.pdf',
        content: invoicePDF,
      },
    ],
  };

  await transporter.sendMail(mailOptions);
};

// =========================== Middleware =================================== //

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) {
    logger.warn('Unauthorized access attempt.', { url: req.originalUrl });
    return res.status(401).json({ error: '❌ Unauthorized access. Please log in.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) {
      logger.warn('Invalid token provided.', { token });
      return res.status(403).json({ error: '❌ Forbidden. Invalid token.' });
    }
    req.user = decodedUser;
    next();
  });
};

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) {
    logger.warn('Admin access denied. No token provided.', { url: req.originalUrl });
    return res.status(403).json({ error: '❌ Access denied: No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      logger.warn('Admin access denied. Invalid token or insufficient permissions.', { token, userRole: decodedUser?.role });
      return res.status(403).json({ error: '❌ Access denied: Insufficient permissions.' });
    }
    req.user = decodedUser;
    next();
  });
};

// Premium Membership Check Middleware
const checkPremium = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (user && user.isPremium) {
    next();
  } else {
    res.status(403).json({ error: '❌ Access denied: Premium membership required.' });
  }
});

// Rate Limiting Middleware
const createRateLimiter = (options) => rateLimit(options);

const generalLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
  message: { error: '❌ Too many requests from this IP, please try again later.' },
});

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: '❌ Too many authentication attempts, please try again later.' },
});

// =========================== Express App Setup ============================ //

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: CORS_ORIGIN.split(',').map(origin => origin.trim()), // Allow multiple origins if needed
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// =========================== Global Middleware ============================ //

// Apply general rate limiter to all requests
app.use(generalLimiter);

// Body Parsers (excluding Stripe Webhook Route)
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
app.use(
  cors({
    origin: CORS_ORIGIN.split(',').map(origin => origin.trim()), // Allow multiple origins if needed
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

// HTTP Request Logging
app.use(
  morgan(NODE_ENV === 'production' ? 'combined' : 'dev', {
    stream: { write: (msg) => logger.info(msg.trim()) },
  })
);

// Response Compression
app.use(compression());

// Cookie Parser
app.use(cookieParser());

// Static Files Serving with Caching
app.use(
  express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: false,
  })
);

// Session Management
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: NODE_ENV === 'production', // Ensure HTTPS in production
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Apply rate limiter to authentication routes
app.use(['/api/login', '/api/signup'], authLimiter);

// =========================== OAuth Routes =============================== //

// Google OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/login' }),
  asyncHandler(async (req, res) => {
    try {
      const token = generateToken(req.user);

      res.cookie('token', token, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      });

      logger.info(`✅ User logged in via Google: ${req.user.email}`, { userId: req.user._id });

      res.redirect('/dashboard');
    } catch (error) {
      logger.error('❌ Google OAuth callback error:', error);
      res.status(500).json({ error: '❌ Server error during authentication.' });
    }
  })
);

// =========================== Static Routes ================================ //

// Redirect /login to /auth/login
app.get('/login', (req, res) => {
  res.redirect('/auth/login');
});

// Redirect /signup to /auth/signup
app.get('/signup', (req, res) => {
  res.redirect('/auth/signup');
});

// Serve /auth/login, /auth/signup, /auth, etc., with optional redirect if authenticated
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
  {
    route: '/auth',
    file: 'auth/auth.html',
    redirectIfAuthenticated: true,
  },
  { route: '/', file: 'index.html' },
  {
    route: '/admin/login',
    file: 'admin/login.html',
    redirectIfAuthenticated: true,
  },
];

// Define routes from the definedRoutes array
definedRoutes.forEach(({ route, file, redirectIfAuthenticated: redirectIfAuth }) => {
  if (redirectIfAuth) {
    app.get(
      route,
      (req, res, next) => {
        const authHeader = req.headers.authorization;
        const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
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
});

// Serve /buy and /plus with access control
app.get('/buy', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'buy.html'));
});

app.get('/plus', authenticateToken, checkPremium, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'plus', 'plus.html'));
});

// Additional Protected Routes
app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'dashboard.html'));
});

app.get('/dashboard/tickets', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'dashboard.html'));
});

app.get('/admin', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'admin.html'));
});

// Admin Dashboard Pages
const adminDashboardPages = ['guides', 'tickets', 'logs', 'users', 'dashboard'];
adminDashboardPages.forEach((page) => {
  app.get(`/admin/${page}`, authenticateAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', `${page}.html`));
  });
});

// Dashboard Platform Pages
const dashboardPlatforms = ['macos', 'android', 'chromeos', 'ios', 'linux', 'windows'];
dashboardPlatforms.forEach((platform) => {
  app.get(`/dashboard/${platform}`, authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard', `${platform}.html`));
  });
});

// ========================= API Endpoints =============================== //

// User Registration Endpoint
app.post(
  '/api/signup',
  authLimiter,
  [
    body('name').trim().notEmpty().withMessage('❌ Name is required.'),
    body('email').isEmail().withMessage('❌ Valid email is required.'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('❌ Password must be at least 8 characters long.')
      .matches(/[A-Z]/)
      .withMessage('❌ Password must contain at least one uppercase letter.')
      .matches(/[a-z]/)
      .withMessage('❌ Password must contain at least one lowercase letter.')
      .matches(/[0-9]/)
      .withMessage('❌ Password must contain at least one number.'),
    body('phoneNumber')
      .optional()
      .matches(/^\+?[1-9]\d{1,14}$/)
      .withMessage('❌ Valid phone number is required.'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Signup validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, phoneNumber } = req.body;

    try {
      const existingUser = await User.findOne({ email });

      if (existingUser && existingUser.password) {
        logger.warn('Signup failed: User already exists.', { email });
        return res.status(400).json({ error: '❌ A user with this email already exists.' });
      }

      const hashedPassword = await bcrypt.hash(password, parseInt(BCRYPT_SALT_ROUNDS));
      const sessionID = generateSessionID();

      let user;
      if (existingUser) {
        existingUser.password = hashedPassword;
        existingUser.sessionID = sessionID;
        existingUser.name = name;
        existingUser.phoneNumber = phoneNumber || existingUser.phoneNumber;
        user = await existingUser.save();
      } else {
        user = new User({
          name,
          email,
          password: hashedPassword,
          sessionID,
          role: 'user',
          phoneNumber: phoneNumber || '',
        });
        await user.save();
      }

      const verifyToken = generateToken(user);
      await sendVerificationEmail(user, verifyToken);

      logger.info(`✅ User registered: ${email}`, { userId: user._id });
      res.status(201).json({
        message: '✅ User registered successfully. Please verify your email.',
      });
    } catch (err) {
      if (err.code === 11000) {
        logger.error('Signup error: Duplicate email.', { email });
        res.status(400).json({ error: '❌ Email already in use.' });
      } else {
        logger.error('Signup error:', err);
        res.status(500).json({ error: '❌ Server error. Please try again later.' });
      }
    }
  })
);

// Email Verification Endpoint
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

        logger.info(`✅ User verified: ${user.email}`, { userId: user._id });
        res.redirect('/auth/login');
      } catch (error) {
        logger.error('Email verification error:', error);
        res.status(500).json({ error: '❌ Server error. Please try again later.' });
      }
    });
  })
);

// User Login Endpoint
app.post(
  '/api/login',
  authLimiter,
  [
    body('email').isEmail().withMessage('❌ Valid email is required.'),
    body('password').notEmpty().withMessage('❌ Password is required.'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });

      if (!user || !user.password) {
        logger.warn('Login failed: User does not exist.', { email });
        return res.status(404).json({ error: '❌ User does not exist. Please sign up.' });
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

      logger.info(`✅ User logged in: ${email}`, { userId: user._id });
      res.status(200).json({
        message: '✅ Login successful.',
        userInfo: {
          name: user.name,
          email: user.email,
          lastLogin: user.lastLogin,
          isVerified: user.isVerified,
          role: user.role,
          isPremium: user.isPremium,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
      });
    } catch (err) {
      logger.error('Login error:', err);
      res.status(500).json({ error: '❌ Server error. Please try again later.' });
    }
  })
);

// User Logout Endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict',
  });
  logger.info(`🔒 User logged out: ${req.user.email}`, { userId: req.user.id });
  res.status(200).json({ message: '✅ Logout successful.' });
});

// ========================= Ticketing System ============================= //

// Create a New Ticket
app.post(
  '/api/tickets',
  authenticateToken,
  upload.single('image'),
  [
    body('subject').trim().notEmpty().withMessage('❌ Subject is required.'),
    body('description').trim().notEmpty().withMessage('❌ Description is required.'),
    body('category').trim().notEmpty().withMessage('❌ Category is required.'),
    body('priority')
      .optional()
      .isIn(['low', 'medium', 'high'])
      .withMessage('❌ Invalid priority.'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Ticket creation validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { subject, description, category, priority } = req.body;
    let imageUrl = null;

    if (req.file) {
      imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    }

    try {
      const ticket = new Ticket({
        subject,
        description,
        category,
        priority: priority || 'medium',
        user: req.user.id,
        imageUrl,
      });

      await ticket.save();
      logger.info(`✅ Ticket created: ${subject} by ${req.user.email}`, {
        ticketId: ticket.ticketId,
        userId: req.user.id,
      });
      res.status(201).json({ message: '✅ Ticket created successfully.', ticket });
    } catch (error) {
      logger.error('❌ Error creating ticket:', error);
      res.status(500).json({ error: '❌ Error creating ticket.' });
    }
  })
);

// Get All Tickets (Admin Only)
app.get(
  '/api/tickets/admin',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const tickets = await Ticket.find()
        .populate('user', 'name email')
        .sort({ createdAt: -1 });
      res.json({ tickets });
    } catch (error) {
      logger.error('❌ Error fetching tickets:', error);
      res.status(500).json({ error: '❌ Error fetching tickets.' });
    }
  })
);

// Get User's Tickets with Pagination and Search
app.get(
  '/api/tickets',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 5, search = '' } = req.query;

    const query = {
      user: req.user.id,
      $or: [
        { subject: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ],
    };

    try {
      const tickets = await Ticket.find(query)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

      const total = await Ticket.countDocuments(query);

      res.json({
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        tickets,
      });
    } catch (error) {
      logger.error('❌ Error fetching tickets:', error);
      res.status(500).json({ error: '❌ Error fetching tickets.' });
    }
  })
);

// Get a Single Ticket by ID
app.get(
  '/api/tickets/:id',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Validate ticket ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: '❌ Invalid ticket ID.' });
    }

    try {
      const ticket = await Ticket.findOne({ _id: id, user: req.user.id });

      if (!ticket) {
        return res.status(404).json({ error: '❌ Ticket not found.' });
      }

      res.json(ticket);
    } catch (error) {
      logger.error('❌ Error fetching ticket:', error);
      res.status(500).json({ error: '❌ Error fetching ticket.' });
    }
  })
);

// Add a Response to a Ticket
app.post(
  '/api/tickets/:id/responses',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { message } = req.body;

    // Validate input
    if (!message) {
      return res.status(400).json({ error: '❌ Response message is required.' });
    }

    // Validate ticket ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: '❌ Invalid ticket ID.' });
    }

    try {
      const ticket = await Ticket.findOne({ _id: id, user: req.user.id });

      if (!ticket) {
        return res.status(404).json({ error: '❌ Ticket not found.' });
      }

      // Add user response
      ticket.responses.push({
        sender: 'User',
        message,
      });

      await ticket.save();

      logger.info(`✅ Response added to ticket: ${ticket.ticketId} by ${req.user.email}`, {
        ticketId: ticket.ticketId,
        userId: req.user.id,
      });

      res.json({ message: '✅ Response added successfully.', ticket });
    } catch (error) {
      logger.error('❌ Add Response Error:', error);
      res.status(500).json({ error: '❌ Error adding response.' });
    }
  })
);

// Update Ticket Status (Admin Only)
app.put(
  '/api/tickets/:id/status',
  authenticateAdmin,
  [
    body('status')
      .isIn(['open', 'pending', 'closed'])
      .withMessage('❌ Status must be open, pending, or closed.'),
  ],
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Ticket status update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    // Validate ticket ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: '❌ Invalid ticket ID.' });
    }

    try {
      const ticket = await Ticket.findByIdAndUpdate(
        id,
        { status },
        { new: true }
      );

      if (!ticket) {
        return res.status(404).json({ error: '❌ Ticket not found.' });
      }

      logger.info(`✅ Ticket status updated: ${ticket.ticketId} to ${status} by Admin`, {
        ticketId: ticket.ticketId,
        adminId: req.user.id,
      });

      res.json({ message: `✅ Ticket status updated to ${status}.`, ticket });
    } catch (error) {
      logger.error('❌ Update Ticket Status Error:', error);
      res.status(500).json({ error: '❌ Error updating ticket status.' });
    }
  })
);

// ========================= Users API (Admin) ============================= //

// Get All Users (Admin Only)
app.get(
  '/api/users',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const users = await User.find().select('-password').sort({ createdAt: -1 });
      res.json({ users });
    } catch (error) {
      logger.error('❌ Error fetching users:', error);
      res.status(500).json({ error: '❌ Error fetching users.' });
    }
  })
);

// Create New User (Admin Only)
app.post(
  '/api/users',
  authenticateAdmin,
  [
    body('name').trim().notEmpty().withMessage('❌ Name is required.'),
    body('email').isEmail().withMessage('❌ Valid email is required.'),
    body('role').isIn(['admin', 'supporter', 'user']).withMessage('❌ Invalid role.'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('❌ Password must be at least 8 characters long.')
      .matches(/[A-Z]/)
      .withMessage('❌ Password must contain at least one uppercase letter.')
      .matches(/[a-z]/)
      .withMessage('❌ Password must contain at least one lowercase letter.')
      .matches(/[0-9]/)
      .withMessage('❌ Password must contain at least one number.'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('User creation validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, email, role, password } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        logger.warn('User creation failed: User already exists.', { email });
        return res.status(400).json({ error: '❌ A user with this email already exists.' });
      }

      const hashedPassword = await bcrypt.hash(password, parseInt(BCRYPT_SALT_ROUNDS));
      const sessionID = generateSessionID();

      const user = new User({
        name,
        email,
        password: hashedPassword,
        sessionID,
        role,
        isVerified: true, // Assuming admin creates verified users
      });

      await user.save();
      logger.info(`✅ User created: ${email} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.status(201).json({ message: '✅ User created successfully.', user });
    } catch (error) {
      if (error.code === 11000) {
        logger.error('❌ Error creating user: Duplicate email.', { email: req.body.email });
        res.status(400).json({ error: '❌ Email already in use.' });
      } else {
        logger.error('❌ Error creating user:', error);
        res.status(500).json({ error: '❌ Error creating user.' });
      }
    }
  })
);

// Update User Role (Admin Only)
app.put(
  '/api/users/:id/role',
  authenticateAdmin,
  [
    body('role').isIn(['user', 'admin', 'supporter']).withMessage('❌ Role must be user, admin, or supporter.'),
  ],
  asyncHandler(async (req, res) => {
    const { role } = req.body;
    const { id } = req.params;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('User role update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const user = await User.findByIdAndUpdate(
        id,
        { role },
        { new: true }
      );

      if (!user) {
        logger.warn('User not found for role update:', id);
        return res.status(404).json({ error: '❌ User not found.' });
      }

      logger.info(`✅ User role updated: ${user.email} to ${role} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.json({ message: `✅ User role updated to ${role}.`, user });
    } catch (error) {
      logger.error('❌ Error updating user role:', error);
      res.status(500).json({ error: '❌ Error updating user role.' });
    }
  })
);

// Deactivate User (Admin Only)
app.put(
  '/api/users/:id/deactivate',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    try {
      const user = await User.findByIdAndUpdate(
        id,
        { status: 'inactive' },
        { new: true }
      );

      if (!user) {
        logger.warn('User not found for deactivation:', id);
        return res.status(404).json({ error: '❌ User not found.' });
      }

      logger.info(`✅ User deactivated: ${user.email} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.json({ message: '✅ User deactivated successfully.', user });
    } catch (error) {
      logger.error('❌ Error deactivating user:', error);
      res.status(500).json({ error: '❌ Error deactivating user.' });
    }
  })
);

// ========================= Dashboard Endpoint ========================= //

app.get(
  '/api/dashboard-data',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const totalUsers = await User.countDocuments({ role: { $ne: 'admin' }, status: 'active' });
      const openTickets = await Ticket.countDocuments({ status: 'open' });
      const pendingTickets = await Ticket.countDocuments({ status: 'pending' });
      const guides = await Guide.countDocuments();

      // Example chart data (customize as needed)
      const chartData = {
        labels: ['January', 'February', 'March', 'April', 'May', 'June'],
        openTickets: [12, 19, 3, 5, 2, 3],
        closedTickets: [7, 11, 5, 8, 3, 7],
      };

      // Example recent activities (customize as needed)
      const recentActivities = [
        { description: 'User John Doe created a new guide.', timestamp: '2024-04-01 10:00' },
        { description: 'Admin Jane Smith closed ticket #123.', timestamp: '2024-04-01 09:30' },
      ];

      res.json({
        totalUsers,
        openTickets,
        pendingTickets,
        guides,
        chartData,
        recentActivities,
      });
    } catch (error) {
      logger.error('❌ Error fetching dashboard data:', error);
      res.status(500).json({ error: '❌ Error fetching dashboard data.' });
    }
  })
);

// ========================= Guides API ========================= //

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
      logger.error('❌ Error fetching popular guides:', error);
      res.status(500).json({ error: '❌ Error fetching popular guides.' });
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
        return res.status(404).json({ error: '❌ Guide not found.' });
      }

      // Increment view count
      guide.views += 1;
      await guide.save();

      res.json(guide);
    } catch (error) {
      logger.error('❌ Error fetching guide by category and slug:', {
        error,
        params: req.params,
      });
      res.status(500).json({ error: '❌ Internal Server Error' });
    }
  })
);

/**
 * Fetch a single guide by ID.
 */
app.get(
  '/api/guides/id/:id',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const guide = await Guide.findById(req.params.id);
      if (!guide) return res.status(404).json({ error: '❌ Guide not found.' });

      // Increment view count
      guide.views += 1;
      await guide.save();

      res.json({ guide });
    } catch (error) {
      logger.error('❌ Error fetching guide:', error);
      res.status(500).json({ error: '❌ Error fetching guide.' });
    }
  })
);

/**
 * Fetch all guides, with optional filtering by category, tag, or search.
 */
app.get(
  '/api/guides',
  authenticateToken,
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
      logger.error('❌ Error fetching guides:', error);
      res.status(500).json({ error: '❌ Error fetching guides.' });
    }
  })
);

/**
 * Create a new guide.
 */
app.post(
  '/api/guides',
  authenticateAdmin,
  upload.single('bannerImage'),
  [
    body('title').trim().notEmpty().withMessage('❌ Title is required.'),
    body('content').trim().notEmpty().withMessage('❌ Content is required.'),
    body('category').trim().notEmpty().withMessage('❌ Category is required.'),
    body('tags').optional().isArray().withMessage('❌ Tags must be an array.'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Guide creation validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { title, subtitle, summary, content, tags, category } = req.body;
      const bannerImage = req.file ? `/uploads/${req.file.filename}` : '';

      // Generate unique slug
      let slug = generateSlug(title);
      let uniqueSlug = slug;
      let counter = 1;
      while (await Guide.findOne({ slug: uniqueSlug, category })) {
        uniqueSlug = `${slug}-${counter++}`;
      }

      const newGuide = new Guide({
        title,
        slug: uniqueSlug,
        subtitle: subtitle || '',
        summary: summary || '',
        content,
        tags: Array.isArray(tags) ? tags : [],
        category,
        bannerImage,
        author: {
          id: req.user.id,
          name: req.user.name,
          email: req.user.email,
        },
        publishDate: new Date().toLocaleDateString(),
      });

      const savedGuide = await newGuide.save();
      logger.info(`✅ Guide created: ${title} by ${req.user.email}`, {
        guideId: savedGuide._id,
        userId: req.user.id,
      });
      res.status(201).json(savedGuide);
    } catch (error) {
      if (error.code === 11000) {
        logger.error('❌ Duplicate key error:', { error, body: req.body });
        res.status(400).json({
          error: '❌ A guide with the same title and category already exists.',
        });
      } else {
        logger.error('❌ Error creating guide:', { error, body: req.body });
        res.status(500).json({ error: '❌ Error creating guide.' });
      }
    }
  })
);

/**
 * Update an existing guide.
 */
app.put(
  '/api/guides/id/:id',
  authenticateAdmin,
  upload.single('bannerImage'),
  [
    body('title').optional().trim().notEmpty().withMessage('❌ Title cannot be empty.'),
    body('content').optional().trim().notEmpty().withMessage('❌ Content cannot be empty.'),
    body('category').optional().trim().notEmpty().withMessage('❌ Category cannot be empty.'),
    body('tags').optional().isArray().withMessage('❌ Tags must be an array.'),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Guide update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { title, content, category } = req.body;
      const updates = { ...req.body };

      if (title) {
        // Generate unique slug
        let slug = generateSlug(title);
        let uniqueSlug = slug;
        let counter = 1;
        const categoryToUse = category || 'general';
        while (await Guide.findOne({ slug: uniqueSlug, category: categoryToUse })) {
          uniqueSlug = `${slug}-${counter++}`;
        }
        updates.slug = uniqueSlug;
      }

      if (req.file) updates.bannerImage = `/uploads/${req.file.filename}`;

      const updatedGuide = await Guide.findByIdAndUpdate(req.params.id, updates, {
        new: true,
        runValidators: true,
      });

      if (!updatedGuide) return res.status(404).json({ error: '❌ Guide not found.' });

      logger.info(`✅ Guide updated: ${updatedGuide.title} by ${req.user.email}`, {
        guideId: updatedGuide._id,
        userId: req.user.id,
      });
      res.json(updatedGuide);
    } catch (error) {
      if (error.code === 11000) {
        logger.error('❌ Duplicate key error:', { error, body: req.body });
        res.status(400).json({
          error: '❌ A guide with the same title and category already exists.',
        });
      } else {
        logger.error('❌ Error updating guide:', { error, body: req.body });
        res.status(500).json({ error: '❌ Error updating guide.' });
      }
    }
  })
);

/**
 * Delete Guide by ID.
 */
app.delete(
  '/api/guides/id/:id',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const deletedGuide = await Guide.findByIdAndDelete(req.params.id);
      if (!deletedGuide) {
        return res.status(404).json({ error: '❌ Guide not found.' });
      }
      logger.info(`✅ Guide deleted: ${deletedGuide.title} by ${req.user.email}`, {
        guideId: deletedGuide._id,
        userId: req.user.id,
      });
      res.json({ message: '✅ Guide deleted successfully.' });
    } catch (error) {
      logger.error('❌ Error deleting guide:', error);
      res.status(500).json({ error: '❌ Error deleting guide.' });
    }
  })
);

// ========================= Articles Endpoint ============================= //

/**
 * Serve the guide based on category and slug.
 * Note: This route serves an HTML page, not JSON. Ensure you have appropriate front-end handling.
 */
app.get(
  '/articles/:category/:slug',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { category, slug } = req.params;

    try {
      const guide = await Guide.findOne({
        category: new RegExp(`^${category}$`, 'i'),
        slug: new RegExp(`^${slug}$`, 'i'),
      });

      if (!guide) {
        logger.warn('❌ Guide not found for category and slug:', { category, slug });
        return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }

      // Increment view count
      guide.views += 1;
      await guide.save();

      res.sendFile(path.join(__dirname, 'public', 'template.html')); // Ensure this file can fetch the guide details
    } catch (error) {
      logger.error('❌ Error fetching guide by category and slug:', { error, params: req.params });
      res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
    }
  })
);

/**
 * Fetch the guide details for rendering on the client-side.
 * This route can be used by the front-end to fetch guide data via AJAX or similar.
 */
app.get(
  '/api/articles/:category/:slug/details',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { category, slug } = req.params;

    try {
      const guide = await Guide.findOne({
        category: new RegExp(`^${category}$`, 'i'),
        slug: new RegExp(`^${slug}$`, 'i'),
      });

      if (!guide) {
        return res.status(404).json({ error: '❌ Guide not found.' });
      }

      // Increment view count
      guide.views += 1;
      await guide.save();

      res.json({ guide });
    } catch (error) {
      logger.error('❌ Error fetching guide details:', error);
      res.status(500).json({ error: '❌ Error fetching guide details.' });
    }
  })
);

// ========================= Stripe Checkout Session ======================= //

app.post(
  '/api/create-checkout-session',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const YOUR_DOMAIN = BASE_URL;

    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'payment',
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: 'Premium Membership',
                description: 'Access to the /plus features.',
              },
              unit_amount: 5000, // $50.00 in cents
            },
            quantity: 1,
          },
        ],
        success_url: `${YOUR_DOMAIN}/plus?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${YOUR_DOMAIN}/buy`,
        metadata: {
          userId: req.user.id,
        },
      });

      res.json({ url: session.url });
    } catch (error) {
      logger.error('❌ Error creating Stripe Checkout session:', error);
      res.status(500).json({ error: '❌ Unable to create checkout session.' });
    }
  })
);

// =========================== Stripe Webhook Route ======================== //

app.post(
  '/api/stripe-webhook',
  express.raw({ type: 'application/json' }), // Stripe requires raw body
  asyncHandler(async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;

    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
      logger.debug(`✅ Webhook event constructed successfully: ${event.id}`);
    } catch (err) {
      logger.error('❌ Stripe webhook signature verification failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        const userId = session.metadata.userId;

        try {
          const user = await User.findById(userId);
          if (user) {
            user.isPremium = true;
            await user.save();
            logger.info(`✅ User ${user.email} has been upgraded to Premium.`);

            // Generate Invoice
            const transactionId = session.payment_intent; // Assuming payment_intent as transaction ID
            const invoicePDF = await generateInvoice(user, transactionId);

            // Send Invoice Email
            await sendInvoiceEmail(user, transactionId, invoicePDF);
            logger.info(`✅ Invoice sent to user: ${user.email}`);
          } else {
            logger.warn(`User with ID ${userId} not found for premium upgrade.`);
          }
        } catch (error) {
          logger.error('❌ Error updating user premium status:', error);
        }
        break;
      // ... handle other event types if needed
      default:
        logger.warn(`Unhandled event type ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    res.json({ received: true });
  })
);

// ========================= Socket.IO Setup ============================== //

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    logger.warn('Socket.IO authentication failed: Token missing');
    return next(new Error("Authentication error: Token missing"));
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn('Socket.IO authentication failed: Invalid token');
      return next(new Error("Authentication error: Invalid token"));
    }
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  logger.info(`🟢 User connected: ${socket.user.name} (${socket.user.email})`);

  // Join user-specific room
  socket.join(socket.user.id);

  // Listen for chat messages
  socket.on('chatMessage', async (msg) => {
    logger.info(`💬 Message from ${socket.user.name}: ${msg}`);

    // Save message as a response in the latest open ticket
    try {
      const ticket = await Ticket.findOne({ user: socket.user.id, status: 'open' }).sort({ createdAt: -1 });
      if (ticket) {
        ticket.responses.push({
          sender: 'User',
          message: msg,
        });

        await ticket.save();

        // Simulate Support response after a delay
        setTimeout(async () => {
          const supportMessage = `Support: We have received your message regarding "${ticket.subject}". Our team is looking into it.`;
          ticket.responses.push({
            sender: 'Support',
            message: supportMessage,
          });
          await ticket.save();
          // Emit support message to the user
          io.to(socket.user.id).emit('chatMessage', supportMessage);
          logger.info(`✅ Support responded to ticket: ${ticket.ticketId}`);
        }, 1500);

        // Emit user message back to the user
        io.to(socket.user.id).emit('chatMessage', `You: ${msg}`);
      } else {
        socket.emit('chatMessage', 'Support: You have no open tickets. Please create a ticket to start a chat.');
      }
    } catch (error) {
      logger.error('❌ Live Chat Error:', error);
      socket.emit('chatMessage', 'Support: An error occurred while processing your message.');
    }
  });

  socket.on('disconnect', () => {
    logger.info(`🔴 User disconnected: ${socket.user.name} (${socket.user.email})`);
  });
});

// ========================== Error Handling ============================= //

// 404 Handler for API Routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: '❌ Not Found' });
});

// General Error Handler for API Routes
app.use('/api/*', (err, req, res, next) => {
  logger.error('❌ API Server Error:', err.stack);
  res.status(500).json({ error: '❌ Internal Server Error' });
});

// 404 Handler for Non-API Routes
app.use('*', (req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
});

// General Error Handler for Non-API Routes
app.use((err, req, res, next) => {
  logger.error('❌ Server Error:', err.stack);
  res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
});

// =========================== Start Server ================================ //

server.listen(PORT, () => {
  logger.info(`🚀 Server is running on port ${PORT}`);
});