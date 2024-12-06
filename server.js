// server.js

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
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import asyncHandler from 'express-async-handler';
import winston from 'winston';
import useragent from 'express-useragent';
import { Server as SocketIOServer } from 'socket.io';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { body, validationResult } from 'express-validator';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import fetch from 'node-fetch';

// =========================== Environment Configuration ======================= //

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
  MONGODB_URI,
} = process.env;

// =========================== Initialize App ============================ //

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: CORS_ORIGIN, // Restrict to your client's origin in production
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Determine __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =========================== Logger Setup ============================ //

// Configure winston logger
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
    new winston.transports.File({ filename: 'server.log' }),
  ],
});

// ======================== Database Connection ========================== //

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

// ====================== Define Schemas and Models ====================== //

// User Schema
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    googleId: { type: String },
    sessionID: { type: String },
    isVerified: { type: Boolean, default: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    theme: { type: String, default: 'light' },
    phoneNumber: { type: String }, // Optional: For future use
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

// Guide Schema
const guideSchema = new mongoose.Schema(
  {
    guideId: { type: String, default: () => uuidv4(), unique: true },
    title: { type: String, required: true, index: true },
    slug: { type: String, required: true, unique: true },
    subtitle: { type: String },
    summary: { type: String },
    content: { type: String, required: true },
    tags: [{ type: String, index: true }],
    category: { type: String, required: true, index: true },
    bannerImage: { type: String },
    author: {
      id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      name: { type: String, default: '' },
      email: { type: String, default: '' },
    },
    publishDate: { type: Date, default: Date.now },
    views: { type: Number, default: 0, index: true },
  },
  { timestamps: true }
);

guideSchema.index({ slug: 1, category: 1 }, { unique: true });

const Guide = mongoose.model('Guide', guideSchema);

// Ticket Schema
const ticketSchema = new mongoose.Schema(
  {
    ticketId: { type: String, default: () => uuidv4(), unique: true },
    subject: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, enum: ['open', 'pending', 'closed'], default: 'open' },
    priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    category: { type: String },
    createdDate: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const Ticket = mongoose.model('Ticket', ticketSchema);

// Log Schema
const logSchema = new mongoose.Schema(
  {
    logId: { type: String, default: () => uuidv4(), unique: true },
    action: { type: String, required: true },
    user: {
      id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      name: { type: String, required: true },
      email: { type: String, required: true },
    },
    date: { type: Date, default: Date.now },
    details: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: true }
);

const Log = mongoose.model('Log', logSchema);

// ====================== Nodemailer Configuration ========================== //

// Create Nodemailer transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com', // Using Gmail SMTP
  port: 465,
  secure: true, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER, // Your Gmail address
    pass: process.env.EMAIL_APP_PASSWORD, // Your Gmail App Password
  },
});

// Verify transporter configuration
transporter.verify((error, success) => {
  if (error) {
    logger.error('❌ Nodemailer transporter error:', error);
  } else {
    logger.info('✅ Nodemailer transporter is ready to send emails');
  }
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
        const email = profile.emails[0].value;
        let user = await User.findOne({ email });

        if (user) {
          if (!user.googleId) {
            user.googleId = profile.id;
            await user.save();
          }
          return done(null, user);
        }

        user = new User({
          googleId: profile.id,
          name: profile.displayName,
          email: email,
          isVerified: true,
          role: 'user',
        });

        await user.save();

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

// =========================== Multer Configuration ========================= //

// Multer configuration for file uploads (e.g., banner images)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = `${Date.now()}-${uuidv4()}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({ storage: storage });

// =========================== Middleware Setup =========================== //

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
      secure: NODE_ENV === 'production', // Ensure HTTPS in production
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(useragent.express());

// =========================== Rate Limiting =========================== //

// Apply rate limiting to sensitive endpoints
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: '❌ Too many requests from this IP, please try again later.',
  },
});

app.use('/api/login', limiter);
app.use('/api/signup', limiter);

// =========================== Authentication Middleware ============================ //

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
      .json({ error: '❌ Unauthorized access. Please log in.' });
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

/**
 * Authenticate Admin Users
 */
const authenticateAdmin = (req, res, next) => {
  const token =
    req.cookies.token ||
    (req.headers.authorization &&
      req.headers.authorization.split(' ')[1]);
  if (!token) {
    logger.warn('Admin access denied. No token provided.', {
      url: req.originalUrl,
    });
    return res.status(403).json({ error: '❌ Access denied: No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      logger.warn(
        'Admin access denied. Invalid token or insufficient permissions.',
        { token, userRole: decodedUser?.role }
      );
      return res.status(403).json({ error: '❌ Access denied: Insufficient permissions.' });
    }
    req.user = decodedUser;
    next();
  });
};

// =========================== Helper Functions ============================ //

/**
 * Send Login Notification Email
 * @param {Object} user - User object
 * @param {String} ip - IP address
 * @param {String} location - Approximate location
 */
const sendLoginNotification = async (user, ip, location) => {
  const mailOptions = {
    from: `"Support Team" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: '📣 New Login Notification',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
        <h2 style="color: #4CAF50;">Hello, ${user.name}!</h2>
        <p>We've detected a new login to your account.</p>
        <table style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Time:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">${new Date().toLocaleString()}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>IP Address:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">${ip}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border: 1px solid #ddd;"><strong>Location:</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">${location}</td>
          </tr>
        </table>
        <p>If this was you, you can safely ignore this email.</p>
        <p>If you didn't log in, please secure your account immediately.</p>
        <hr>
        <p style="font-size: 12px; color: #888;">If you have any questions, feel free to contact our support team.</p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    logger.info(`✅ Login notification email sent to ${user.email}`);
  } catch (error) {
    logger.error('❌ Error sending login notification email:', error);
  }
};

/**
 * Get Geolocation from IP Address using ip-api.com
 * @param {String} ip - IP address
 * @returns {String} - Location string
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
 * Retrieve client's IP address from request
 * @param {Object} req - Express request object
 * @returns {String} - IP address
 */
const getClientIP = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
};

// =========================== Routes ============================ //

// Serve Static Routes with Optional Authentication
const staticRoutes = [
  { route: '/auth/login', file: 'auth/login.html' },
  { route: '/auth/signup', file: 'auth/signup.html' },
  { route: '/auth', file: 'auth/auth.html' },
  { route: '/admin/login', file: 'admin/login.html' },
  { route: '/admin', file: 'admin/admin.html', authenticate: true }, // Protected route
  { route: '/guides', file: 'guides/guides.html' },
  { route: '/tickets', file: 'tickets/tickets.html' },
  { route: '/users', file: 'users/users.html', authenticate: true }, // Protected route
  { route: '/', file: 'index.html' },
  // Removed /forum and related routes
  // Add more routes as needed
];

// Serve Static Routes
staticRoutes.forEach(({ route, file, authenticate: requiresAuth }) => {
  if (requiresAuth) {
    app.get(route, authenticateAdmin, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  } else {
    app.get(route, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  }
});

// ==================== Admin Dashboard Routes ===================== //

// Admin Dashboard Pages
const adminDashboardPages = ['guides', 'tickets', 'logs', 'users', 'dashboard'];

// Serve Admin Dashboard Pages
adminDashboardPages.forEach((page) => {
  app.get(`/admin/${page}`, authenticateAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', `${page}.html`));
  });
});

// ==================== Dashboard Platform Routes ===================== //

const dashboardPlatforms = ['macos', 'android', 'chromeos', 'ios', 'linux', 'windows'];

// Serve Dashboard Platform Pages
dashboardPlatforms.forEach((platform) => {
  app.get(`/dashboard/${platform}`, authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard', `${platform}.html`));
  });
});

// ========================== OAuth Routes ========================= //

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/login' }),
  async (req, res) => {
    try {
      // Generate JWT
      const token = jwt.sign(
        { id: req.user._id, email: req.user.email, role: req.user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      // Set JWT in HTTP-only cookie
      res.cookie('token', token, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      });

      // Get client's IP and location
      const ip = getClientIP(req);
      const location = await getGeolocation(ip);

      // Send login notification email
      await sendLoginNotification(req.user, ip, location);

      logger.info(`✅ User logged in via Google: ${req.user.email}`, { userId: req.user._id, ip, location });

      res.redirect('/admin'); // Redirect to desired page after login
    } catch (error) {
      logger.error('❌ Google OAuth callback error:', error);
      res.status(500).json({ error: '❌ Server error during authentication.' });
    }
  }
);

// ========================== API Endpoints ========================= //

// User Registration Endpoint
app.post(
  '/api/signup',
  [
    body('name').trim().notEmpty().withMessage('Name is required.'),
    body('email').isEmail().withMessage('Valid email is required.'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long.')
      .matches(/[A-Z]/)
      .withMessage('Password must contain at least one uppercase letter.')
      .matches(/[a-z]/)
      .withMessage('Password must contain at least one lowercase letter.')
      .matches(/[0-9]/)
      .withMessage('Password must contain at least one number.'),
    body('phoneNumber')
      .optional()
      .matches(/^\+?[1-9]\d{1,14}$/)
      .withMessage('Valid phone number is required.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
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
        return res
          .status(400)
          .json({ error: '❌ A user with this email already exists.' });
      }

      const hashedPassword = await bcrypt.hash(password, parseInt(BCRYPT_SALT_ROUNDS));
      const sessionID = uuidv4();

      let user;
      if (existingUser) {
        existingUser.password = hashedPassword;
        existingUser.sessionID = sessionID;
        existingUser.name = name; // Update name if provided
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

      logger.info(`✅ User registered: ${email}`, { userId: user._id });
      res.status(201).json({
        message: '✅ User registered successfully. Please log in to continue.',
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

// Login Endpoint
app.post(
  '/api/login',
  [
    body('email').isEmail().withMessage('Valid email is required.'),
    body('password').notEmpty().withMessage('Password is required.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
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
        return res
          .status(404)
          .json({ error: '❌ User does not exist. Please sign up.' });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        logger.warn('Login failed: Invalid credentials.', { email });
        return res.status(401).json({ error: '❌ Invalid credentials.' });
      }

      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      res.cookie('token', token, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000, // 1 hour
      });

      // Get client's IP and location
      const ip = getClientIP(req);
      const location = await getGeolocation(ip);

      // Send login notification email
      await sendLoginNotification(user, ip, location);

      logger.info(`✅ User logged in: ${email}`, { userId: user._id, ip, location });

      res.status(200).json({
        message: '✅ Login successful.',
        userInfo: {
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } catch (err) {
      logger.error('Login error:', err);
      res.status(500).json({ error: '❌ Server error. Please try again later.' });
    }
  })
);

// Logout Endpoint
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', {
    path: '/',
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict',
  });
  logger.info(`🔒 User logged out.`);
  res.status(200).json({ message: '✅ Logout successful.' });
});

// ==================== CRUD API for Guides ===================== //

// Get all guides
app.get(
  '/api/guides',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const guides = await Guide.find().sort({ createdAt: -1 });
      res.json({ guides });
    } catch (error) {
      logger.error('Error fetching guides:', error);
      res.status(500).json({ error: '❌ Error fetching guides.' });
    }
  })
);

// Get guide by ID
app.get(
  '/api/guides/id/:id',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const guide = await Guide.findById(req.params.id);
      if (!guide) {
        return res.status(404).json({ error: 'Guide not found.' });
      }
      res.json({ guide });
    } catch (error) {
      logger.error('Error fetching guide:', error);
      res.status(500).json({ error: 'Error fetching guide.' });
    }
  })
);

// Create a new guide with file upload
app.post(
  '/api/guides',
  authenticateAdmin, // Ensure only admins can create guides
  upload.single('bannerImage'), // Handle single file upload
  [
    body('title').trim().notEmpty().withMessage('Title is required.'),
    body('content').trim().notEmpty().withMessage('Content is required.'),
    body('category').trim().notEmpty().withMessage('Category is required.'),
    body('tags').optional().isArray().withMessage('Tags must be an array.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Guide creation validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { title, subtitle, summary, content, tags, category } = req.body;
      const bannerImage = req.file ? `/uploads/${req.file.filename}` : '';

      // Generate a unique slug
      let slug = title
        .toLowerCase()
        .trim()
        .replace(/[^\w\s-]/g, '')
        .replace(/[\s_-]+/g, '-')
        .replace(/^-+|-+$/g, '');

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
        publishDate: new Date(),
      });

      const savedGuide = await newGuide.save();
      logger.info(`✅ Guide created: ${title} by ${req.user.email}`, {
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

// Update an existing guide
app.put(
  '/api/guides/id/:id',
  authenticateAdmin, // Ensure only admins can update guides
  upload.single('bannerImage'), // Handle single file upload
  [
    body('title').optional().trim().notEmpty().withMessage('Title cannot be empty.'),
    body('content').optional().trim().notEmpty().withMessage('Content cannot be empty.'),
    body('category').optional().trim().notEmpty().withMessage('Category cannot be empty.'),
    body('tags').optional().isArray().withMessage('Tags must be an array.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Guide update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { title, content, category } = req.body;
      const updates = { ...req.body };

      if (title) {
        // Generate a unique slug
        let slug = title
          .toLowerCase()
          .trim()
          .replace(/[^\w\s-]/g, '')
          .replace(/[\s_-]+/g, '-')
          .replace(/^-+|-+$/g, '');

        let uniqueSlug = slug;
        let counter = 1;

        while (await Guide.findOne({ slug: uniqueSlug, category: category || 'general' })) {
          uniqueSlug = `${slug}-${counter++}`;
        }

        updates.slug = uniqueSlug;
      }

      if (req.file) {
        updates.bannerImage = `/uploads/${req.file.filename}`;
      }

      const updatedGuide = await Guide.findByIdAndUpdate(req.params.id, updates, {
        new: true,
        runValidators: true,
      });

      if (!updatedGuide) {
        logger.warn('Guide not found for update:', req.params.id);
        return res.status(404).json({ error: 'Guide not found.' });
      }

      logger.info(`✅ Guide updated: ${updatedGuide.title} by ${req.user.email}`, {
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

// Delete a guide by ID
app.delete(
  '/api/guides/id/:id',
  authenticateAdmin, // Ensure only admins can delete guides
  asyncHandler(async (req, res) => {
    try {
      const deletedGuide = await Guide.findByIdAndDelete(req.params.id);
      if (!deletedGuide) {
        logger.warn('Guide not found for deletion:', req.params.id);
        return res.status(404).json({ error: 'Guide not found.' });
      }
      logger.info(`✅ Guide deleted: ${deletedGuide.title} by ${req.user.email}`, {
        guideId: deletedGuide._id,
        userId: req.user.id,
      });
      res.json({ message: '✅ Guide deleted successfully.' });
    } catch (error) {
      logger.error('Error deleting guide:', error);
      res.status(500).json({ error: 'Error deleting guide.' });
    }
  })
);

// ==================== CRUD API for Tickets ===================== //

// Get all tickets (Admin Only)
app.get(
  '/api/tickets',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const tickets = await Ticket.find()
        .populate('createdBy', 'name email')
        .populate('assignedTo', 'name email')
        .sort({ createdAt: -1 });
      res.json({ tickets });
    } catch (error) {
      logger.error('Error fetching tickets:', error);
      res.status(500).json({ error: '❌ Error fetching tickets.' });
    }
  })
);

// Create a new ticket
app.post(
  '/api/tickets',
  authenticateToken,
  [
    body('subject').trim().notEmpty().withMessage('Subject is required.'),
    body('description').trim().notEmpty().withMessage('Description is required.'),
    body('category').trim().notEmpty().withMessage('Category is required.'),
    body('priority')
      .optional()
      .isIn(['low', 'medium', 'high'])
      .withMessage('Invalid priority.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Ticket creation validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { subject, description, category, priority } = req.body;

      const ticket = new Ticket({
        subject,
        description,
        category,
        priority: priority || 'medium',
        createdBy: req.user.id,
      });

      await ticket.save();
      logger.info(`✅ Ticket created: ${subject} by ${req.user.email}`, {
        ticketId: ticket.ticketId,
        userId: req.user.id,
      });
      res.status(201).json({ message: '✅ Ticket created successfully.', ticket });
    } catch (error) {
      logger.error('Error creating ticket:', error);
      res.status(500).json({ error: '❌ Error creating ticket.' });
    }
  })
);

// Update ticket status (Admin Only)
app.put(
  '/api/tickets/:id/status',
  authenticateAdmin,
  [
    body('status')
      .isIn(['open', 'pending', 'closed'])
      .withMessage('Status must be open, pending, or closed.'),
  ],
  asyncHandler(async (req, res) => {
    const { status } = req.body;

    // Input Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Ticket status update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const ticket = await Ticket.findByIdAndUpdate(
        req.params.id,
        { status },
        { new: true }
      );

      if (!ticket) {
        logger.warn('Ticket not found for status update:', req.params.id);
        return res.status(404).json({ error: '❌ Ticket not found.' });
      }

      logger.info(`✅ Ticket status updated: ${ticket.subject} to ${status} by Admin`, {
        ticketId: ticket.ticketId,
        adminId: req.user.id,
      });
      res.json({ message: `✅ Ticket status updated to ${status}.`, ticket });
    } catch (error) {
      logger.error('Error updating ticket status:', error);
      res.status(500).json({ error: '❌ Error updating ticket status.' });
    }
  })
);

// ==================== CRUD API for Users ===================== //

// Get all users (Admin Only)
app.get(
  '/api/users',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const users = await User.find().select('-password').sort({ createdAt: -1 });
      res.json({ users });
    } catch (error) {
      logger.error('Error fetching users:', error);
      res.status(500).json({ error: '❌ Error fetching users.' });
    }
  })
);

// Create a new user (Admin Only)
app.post(
  '/api/users',
  authenticateAdmin,
  [
    body('name').trim().notEmpty().withMessage('Name is required.'),
    body('email').isEmail().withMessage('Valid email is required.'),
    body('role').isIn(['admin', 'supporter', 'user']).withMessage('Invalid role.'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long.')
      .matches(/[A-Z]/)
      .withMessage('Password must contain at least one uppercase letter.')
      .matches(/[a-z]/)
      .withMessage('Password must contain at least one lowercase letter.')
      .matches(/[0-9]/)
      .withMessage('Password must contain at least one number.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
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
        return res
          .status(400)
          .json({ error: '❌ A user with this email already exists.' });
      }

      const hashedPassword = await bcrypt.hash(password, parseInt(BCRYPT_SALT_ROUNDS));
      const sessionID = uuidv4();

      const user = new User({
        name,
        email,
        password: hashedPassword,
        sessionID,
        role,
        status: 'active',
      });

      await user.save();

      logger.info(`✅ User created: ${email} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.status(201).json({ message: '✅ User created successfully.', user });
    } catch (error) {
      logger.error('Error creating user:', error);
      res.status(500).json({ error: '❌ Error creating user.' });
    }
  })
);

// Update user role (Admin Only)
app.put(
  '/api/users/:id/role',
  authenticateAdmin,
  [
    body('role').isIn(['user', 'admin', 'supporter']).withMessage('Role must be user, admin, or supporter.'),
  ],
  asyncHandler(async (req, res) => {
    const { role } = req.body;

    // Input Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('User role update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const user = await User.findByIdAndUpdate(
        req.params.id,
        { role },
        { new: true }
      );

      if (!user) {
        logger.warn('User not found for role update:', req.params.id);
        return res.status(404).json({ error: '❌ User not found.' });
      }

      logger.info(`✅ User role updated: ${user.email} to ${role} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.json({ message: `✅ User role updated to ${role}.`, user });
    } catch (error) {
      logger.error('Error updating user role:', error);
      res.status(500).json({ error: '❌ Error updating user role.' });
    }
  })
);

// Deactivate a user (Admin Only)
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
        return res.status(404).json({ error: '❌ User not found.' });
      }

      logger.info(`✅ User deactivated: ${user.email} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.json({ message: '✅ User deactivated successfully.', user });
    } catch (error) {
      logger.error('Error deactivating user:', error);
      res.status(500).json({ error: '❌ Error deactivating user.' });
    }
  })
);

// Update user details (Admin Only)
app.put(
  '/api/users/:id',
  authenticateAdmin,
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty.'),
    body('email').optional().isEmail().withMessage('Valid email is required.'),
    body('role').optional().isIn(['admin', 'supporter', 'user']).withMessage('Invalid role.'),
    body('password')
      .optional()
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long.')
      .matches(/[A-Z]/)
      .withMessage('Password must contain at least one uppercase letter.')
      .matches(/[a-z]/)
      .withMessage('Password must contain at least one lowercase letter.')
      .matches(/[0-9]/)
      .withMessage('Password must contain at least one number.'),
  ],
  asyncHandler(async (req, res) => {
    // Input Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('User update validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const updates = { ...req.body };

      if (updates.password) {
        updates.password = await bcrypt.hash(updates.password, parseInt(BCRYPT_SALT_ROUNDS));
      }

      const user = await User.findByIdAndUpdate(
        req.params.id,
        updates,
        { new: true, runValidators: true }
      ).select('-password');

      if (!user) {
        logger.warn('User not found for update:', req.params.id);
        return res.status(404).json({ error: '❌ User not found.' });
      }

      logger.info(`✅ User updated: ${user.email} by Admin`, {
        userId: user._id,
        adminId: req.user.id,
      });
      res.json({ message: '✅ User updated successfully.', user });
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Duplicate email error:', { error, body: req.body });
        res.status(400).json({ error: '❌ Email already in use.' });
      } else {
        logger.error('Error updating user:', error);
        res.status(500).json({ error: '❌ Error updating user.' });
      }
    }
  })
);

// ==================== CRUD API for Users ===================== //

// Get dashboard data
app.get(
  '/api/dashboard-data',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const totalUsers = await User.countDocuments({ role: { $ne: 'admin' }, status: 'active' });
      const openTickets = await Ticket.countDocuments({ status: 'open' });
      const pendingTickets = await Ticket.countDocuments({ status: 'pending' });
      const guides = await Guide.countDocuments();

      // Example chart data
      const chartData = {
        labels: ['January', 'February', 'March', 'April', 'May', 'June'],
        openTickets: [12, 19, 3, 5, 2, 3],
        closedTickets: [7, 11, 5, 8, 3, 7],
      };

      // Example recent activities (you can customize this)
      const recentActivities = [
        { description: 'User John Doe created a new guide.', timestamp: '2024-04-01 10:00' },
        { description: 'Admin Jane Smith closed ticket #123.', timestamp: '2024-04-01 09:30' },
        // Add more activities as needed
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
      logger.error('Error fetching dashboard data:', error);
      res.status(500).json({ error: '❌ Error fetching dashboard data.' });
    }
  })
);

// ==================== Search API for Guides ===================== //

// Search Guides Endpoint with Pagination
app.get(
  '/api/guides/search',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const query = req.query.q;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    if (!query) {
      return res.status(400).json({ error: '❌ Query parameter "q" is required.' });
    }

    try {
      const regex = new RegExp(query, 'i'); // Case-insensitive regex
      const guides = await Guide.find({
        $or: [
          { title: { $regex: regex } },
          { content: { $regex: regex } },
          { tags: { $regex: regex } },
        ],
      })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

      const total = await Guide.countDocuments({
        $or: [
          { title: { $regex: regex } },
          { content: { $regex: regex } },
          { tags: { $regex: regex } },
        ],
      });

      res.json({
        total,
        page,
        pages: Math.ceil(total / limit),
        guides,
      });
    } catch (error) {
      logger.error('Error searching guides:', error);
      res.status(500).json({ error: '❌ Error searching guides.' });
    }
  })
);

// ==================== Route to Serve Articles by Category and Slug ===================== //

app.get(
  '/articles/:category/:slug',
  authenticateToken, // Ensure only authenticated users can access articles
  asyncHandler(async (req, res) => {
    const { category, slug } = req.params;

    try {
      const guide = await Guide.findOne({
        category: new RegExp(`^${category}$`, 'i'),
        slug: new RegExp(`^${slug}$`, 'i'),
      });

      if (!guide) {
        logger.warn('Guide not found for category and slug:', { category, slug });
        return res
          .status(404)
          .sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }

      // Optionally, you can track views or perform other operations here
      guide.views += 1;
      await guide.save();

      // Serve the template.html file (ensure it can fetch and display the guide data)
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

// ========================== Socket.IO Setup ============================ //

io.on('connection', (socket) => {
  logger.info('🟢 A user connected via Socket.IO');

  socket.on('chat message', (msg) => {
    logger.info(`💬 Message received: ${msg}`);
    io.emit('chat message', msg);
  });

  socket.on('disconnect', () => {
    logger.info('🔴 A user disconnected from Socket.IO');
  });
});

// ========================== Error Handling ============================= //

// 404 Handler for API Routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: '❌ Not Found' });
});

// 404 Handler for Non-API Routes
app.use('*', (req, res) => {
  res
    .status(404)
    .sendFile(path.join(__dirname, 'public', 'error', '404.html'));
});

// General Error Handler for All Routes
app.use((err, req, res, next) => {
  logger.error('❌ Server error:', err.stack);
  if (req.path.startsWith('/api')) {
    res.status(500).json({ error: '❌ Internal Server Error' });
  } else {
    res
      .status(500)
      .sendFile(path.join(__dirname, 'public', 'error', '500.html'));
  }
});

// =========================== Start Server ============================== //

server.listen(PORT, () => {
  logger.info(`🚀 Server is running on port ${PORT}`);
});
