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
} = process.env;

// Determine __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================= Logger Setup ============================== //
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
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    googleId: { type: String },
    sessionID: { type: String },
    isVerified: { type: Boolean, default: false },
    lastLogin: { type: Date },
    role: { type: String, enum: ['user', 'admin', 'supporter'], default: 'user' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    theme: { type: String, default: 'light' },
    phoneNumber: { type: String },
    profileSetUp: { type: Boolean, default: false }, // Added field to track profile setup
  },
  { timestamps: true }
);

// Response Schema for Tickets
const responseSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

// Ticket Schema
const ticketSchema = new mongoose.Schema(
  {
    ticketId: { type: String, default: () => uuidv4(), unique: true },
    subject: { type: String, required: true, maxlength: 100 },
    description: { type: String, required: true, maxlength: 1000 },
    imageUrl: { type: String },
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

transporter.verify((error) => {
  if (error) {
    logger.error('❌ Nodemailer transporter error:', error);
  } else {
    logger.info('✅ Nodemailer transporter is ready to send emails');
  }
});

// ========================= Passport Configuration ========================= //
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

        user = await User.create({
          googleId: profile.id,
          name: profile.displayName,
          email: email,
          isVerified: true, // Auto-verify Google users
          role: 'user',
        });

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
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = `${Date.now()}-${uuidv4()}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
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

const generateSessionID = () => crypto.randomBytes(16).toString('hex');

const sendVerificationEmail = async (user, token) => {
  const verifyLink = `${BASE_URL}/api/verify-email?token=${token}`;
  const mailOptions = {
    from: `"No Reply" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: '🔒 Verify Your Email',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Welcome, ${user.name}!</h2>
        <p>Please verify your email address:</p>
        <a href="${verifyLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
        <p>If you did not sign up, ignore this email.</p>
      </div>
    `,
  };
  await transporter.sendMail(mailOptions);
};

const generateSlug = (text) => {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

// =========================== Middleware =================================== //
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

// =========================== Express App Setup ============================ //
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: CORS_ORIGIN.split(',').map(origin => origin.trim()),
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Global Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: CORS_ORIGIN.split(',').map(origin => origin.trim()),
    credentials: true,
    optionsSuccessStatus: 200,
  })
);
app.use(
  morgan(NODE_ENV === 'production' ? 'combined' : 'dev', {
    stream: { write: (msg) => logger.info(msg.trim()) },
  })
);
app.use(compression());
app.use(cookieParser());
app.use(
  express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: false,
  })
);
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

// =========================== OAuth Routes =============================== //
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
app.get('/login', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth', 'login.html'));
});
app.get('/signup', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth', 'signup.html'));
});
app.get('/auth', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth', 'auth.html'));
});
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/admin/login', redirectIfAuthenticatedAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

// Middleware to redirect authenticated users
function redirectIfAuthenticated(req, res, next) {
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
}

// Middleware to redirect authenticated admin users
function redirectIfAuthenticatedAdmin(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
      if (!err && decodedUser.role === 'admin') {
        return res.redirect('/admin');
      }
      next();
    });
  } else {
    next();
  }
}

// Defined Static Routes
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

// Apply defined routes
definedRoutes.forEach(({ route, file, redirectIfAuthenticated: redirectIfAuth }) => {
  if (redirectIfAuth) {
    app.get(route, redirectIfAuthenticated, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  } else {
    app.get(route, (req, res) => {
      res.sendFile(path.join(__dirname, 'public', file));
    });
  }
});

// Dashboard Routes
app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'dashboard.html'));
});

// Setup Profile Page
app.get('/setup-profile', authenticateToken, (req, res) => {
  // If user is already set up, redirect to dashboard/profile
  User.findById(req.user.id).then(user => {
    if (user && user.profileSetUp) {
      return res.redirect('/dashboard/profile');
    }
    res.sendFile(path.join(__dirname, 'public', 'setup-profile.html'));
  });
});

app.post('/api/user/setup', authenticateToken, asyncHandler(async (req, res) => {
  const { username, fullname, email } = req.body;
  // Validate fields as needed
  const user = await User.findById(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  // Mark profile as set up
  user.profileSetUp = true;
  // Update user details if provided
  user.name = fullname || user.name;
  user.email = email || user.email;
  await user.save();
  res.json({ message: "✅ Profile has been successfully set up!" });
}));

app.get('/dashboard/profile', authenticateToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user.profileSetUp) {
    // Profile not set up yet, but user tries to access profile page
    // You can redirect or show a message prompting setup
    return res.redirect('/setup-profile');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'profile.html'));
  logger.info(`Profile page served for user: ${req.user.email}`);
}));

// Admin Profile Page
app.get('/admin/profile', authenticateAdmin, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user || user.role !== 'admin') {
    return res.status(403).send("❌ Forbidden: You are not an admin.");
  }
  res.sendFile(path.join(__dirname, 'public', 'admin', 'profile.html'));
}));

app.get('/dashboard/tickets', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'tickets.html'));
});

app.get('/admin', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'admin.html'));
});

const adminDashboardPages = ['guides', 'tickets', 'logs', 'users', 'dashboard'];
adminDashboardPages.forEach((page) => {
  app.get(`/admin/${page}`, authenticateAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', `${page}.html`));
  });
});

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
  [
    body('name').trim().notEmpty().withMessage('❌ Name is required.'),
    body('email').isEmail().withMessage('❌ Valid email is required.'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('❌ Password must be at least 8 characters.')
      .matches(/[A-Z]/).withMessage('❌ Password must contain an uppercase letter.')
      .matches(/[a-z]/).withMessage('❌ Password must contain a lowercase letter.')
      .matches(/[0-9]/).withMessage('❌ Password must contain a number.'),
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

        if (user.isVerified) {
          logger.info(`✅ User already verified: ${user.email}`);
          return res.redirect('/auth/login');
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
  [
    body('message').trim().notEmpty().withMessage('❌ Response message is required.'),
  ],
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { message } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Add response validation failed.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: '❌ Invalid ticket ID.' });
    }

    try {
      const ticket = await Ticket.findOne({ _id: id, user: req.user.id });
      if (!ticket) {
        return res.status(404).json({ error: '❌ Ticket not found.' });
      }

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

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: '❌ Invalid ticket ID.' });
    }

    try {
      const ticket = await Ticket.findByIdAndUpdate(id, { status }, { new: true });
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

// Get All Users
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
      .isLength({ min: 8 }).withMessage('❌ Password must be at least 8 characters.')
      .matches(/[A-Z]/).withMessage('❌ Must contain uppercase.')
      .matches(/[a-z]/).withMessage('❌ Must contain lowercase.')
      .matches(/[0-9]/).withMessage('❌ Must contain a number.'),
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
        isVerified: true,
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
      const user = await User.findByIdAndUpdate(id, { role }, { new: true });
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
      const user = await User.findByIdAndUpdate(id, { status: 'inactive' }, { new: true });
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

      const chartData = {
        labels: ['January', 'February', 'March', 'April', 'May', 'June'],
        openTickets: [12, 19, 3, 5, 2, 3],
        closedTickets: [7, 11, 5, 8, 3, 7],
      };

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

// Search Guides (Public)
app.get(
  '/api/guides/search',
  asyncHandler(async (req, res) => {
    const { q } = req.query;
    if (!q || q.trim() === '') {
      return res.status(400).json({ error: '❌ Search query is required.' });
    }

    try {
      const searchRegex = new RegExp(q, 'i');
      const guides = await Guide.find({
        $or: [
          { title: searchRegex },
          { summary: searchRegex },
          { content: searchRegex },
          { tags: searchRegex },
        ],
      })
        .sort({ views: -1 })
        .select('title summary tags category views');

      res.status(200).json({ guides, total: guides.length });
    } catch (error) {
      logger.error('❌ Error searching guides:', error);
      res.status(500).json({ error: 'Internal server error while searching guides.' });
    }
  })
);

// Popular Guides (Public)
app.get(
  '/api/guides/popular',
  asyncHandler(async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 6, 20);
    try {
      const popularGuides = await Guide.find()
        .sort({ views: -1 })
        .limit(limit)
        .select('title summary tags category views');

      res.status(200).json({ guides: popularGuides, total: popularGuides.length });
    } catch (error) {
      logger.error('❌ Error fetching popular guides:', error);
      res.status(500).json({ error: 'Internal server error while fetching popular guides.' });
    }
  })
);

// Fetch a single guide by category/slug
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

      guide.views += 1;
      await guide.save();

      res.json(guide);
    } catch (error) {
      logger.error('❌ Error fetching guide:', error);
      res.status(500).json({ error: '❌ Internal Server Error' });
    }
  })
);

// Fetch guide by ID
app.get(
  '/api/guides/id/:id',
  asyncHandler(async (req, res) => {
    try {
      const guide = await Guide.findById(req.params.id);
      if (!guide) return res.status(404).json({ error: '❌ Guide not found.' });

      guide.views += 1;
      await guide.save();

      res.json({ guide });
    } catch (error) {
      logger.error('❌ Error fetching guide:', error);
      res.status(500).json({ error: '❌ Error fetching guide.' });
    }
  })
);

// Fetch all guides with optional filters
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
      logger.error('❌ Error fetching guides:', error);
      res.status(500).json({ error: '❌ Error fetching guides.' });
    }
  })
);

// Create a new guide (Admin)
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

// Update an existing guide (Admin)
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

// Delete Guide by ID (Admin)
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

// Serve article template
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
        logger.warn('❌ Guide not found:', { category, slug });
        return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }

      guide.views += 1;
      await guide.save();

      res.sendFile(path.join(__dirname, 'public', 'template.html'));
    } catch (error) {
      logger.error('❌ Error fetching guide by category and slug:', { error, params: req.params });
      res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
    }
  })
);

// Fetch guide details
app.get(
  '/api/articles/:category/:slug/details',
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

      guide.views += 1;
      await guide.save();

      res.json({ guide });
    } catch (error) {
      logger.error('❌ Error fetching guide details:', error);
      res.status(500).json({ error: '❌ Error fetching guide details.' });
    }
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
  socket.join(socket.user.id);

  socket.on('chatMessage', async (msg) => {
    logger.info(`💬 Message from ${socket.user.name}: ${msg}`);

    try {
      const ticket = await Ticket.findOne({ user: socket.user.id, status: 'open' }).sort({ createdAt: -1 });
      if (ticket) {
        ticket.responses.push({ sender: 'User', message: msg });
        await ticket.save();

        setTimeout(async () => {
          const supportMessage = `Support: We have received your message regarding "${ticket.subject}". Our team is looking into it.`;
          ticket.responses.push({ sender: 'Support', message: supportMessage });
          await ticket.save();
          io.to(socket.user.id).emit('chatMessage', supportMessage);
          logger.info(`✅ Support responded to ticket: ${ticket.ticketId}`);
        }, 1500);

        io.to(socket.user.id).emit('chatMessage', `You: ${msg}`);
      } else {
        socket.emit('chatMessage', 'Support: You have no open tickets. Please create a ticket.');
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
  logger.info(`🚀 Server is running on PORT ${PORT}`);
});
