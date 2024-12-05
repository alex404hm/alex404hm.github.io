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
import useragent from 'express-useragent';
import { Server } from 'socket.io';
import http from 'http';
import { v4 as uuidv4 } from 'uuid';
import { body, validationResult } from 'express-validator';
import multer from 'multer';

// Initialize Environment
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
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
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
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    googleId: { type: String },
    sessionID: { type: String },
    isVerified: { type: Boolean, default: false },
    lastLogin: { type: Date },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    theme: { type: String, default: 'light' },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

// Guide Schema
const guideSchema = new mongoose.Schema({
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
}, { timestamps: true });

guideSchema.index({ slug: 1, category: 1 }, { unique: true });

const Guide = mongoose.model('Guide', guideSchema);

// Ticket Schema
const ticketSchema = new mongoose.Schema({
  ticketId: { type: String, default: () => uuidv4(), unique: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, enum: ['open', 'pending', 'closed'], default: 'open' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  category: { type: String },
  createdDate: { type: Date, default: Date.now },
}, { timestamps: true });

const Ticket = mongoose.model('Ticket', ticketSchema);

// Log Schema
const logSchema = new mongoose.Schema({
  logId: { type: String, default: () => uuidv4(), unique: true },
  action: { type: String, required: true },
  user: {
    id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
  },
  date: { type: Date, default: Date.now },
  details: { type: mongoose.Schema.Types.Mixed },
}, { timestamps: true });

const Log = mongoose.model('Log', logSchema);

// Utility Functions
const generateSlug = (text) => text
  .toString()
  .toLowerCase()
  .trim()
  .replace(/[^\w\s-]/g, '')
  .replace(/[\s_-]+/g, '-')
  .replace(/^-+|-+$/g, '');

const createUniqueSlug = async (title, category) => {
  let slug = generateSlug(title);
  let uniqueSlug = slug;
  let counter = 1;

  while (await Guide.findOne({ slug: uniqueSlug, category })) {
    uniqueSlug = `${slug}-${counter++}`;
  }

  return uniqueSlug;
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
          isVerified: true,
          role: 'user',
        });
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

// ========================== Middleware Setup =========================== //

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
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
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(useragent.express());

// ====================== Authentication Middleware ====================== //

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
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

const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) {
    logger.warn('Admin access denied. No token provided.', {
      url: req.originalUrl,
    });
    return res.status(403).json({ error: 'Access Denied: Not Granted Access.' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      logger.warn(
        'Admin access denied. Invalid token or insufficient permissions.',
        { token, userRole: decodedUser?.role }
      );
      return res.status(403).json({ error: 'Access Denied: Not Granted Access.' });
    }
    req.user = decodedUser;
    next();
  });
};

// =============================== Routes ================================ //

app.get('/auth', (req, res) => {
  res.sendFile('auth/auth.html', { root: '.' });
});

app.get('/auth/forgot-password', (req, res) => {
  res.sendFile('auth/forgot-password.html', { root: '.' });
});

app.get('/auth/forgot-email', (req, res) => {
  res.sendFile('auth/forgot-email.html', { root: '.' });
});

app.get('/auth/setup-profile', (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.status(400).sendFile('error/400.html', { root: '.' });
  }
  res.sendFile('auth/setup-profile.html', { root: '.' });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/login' }),
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user._id,
        email: req.user.email,
        role: req.user.role,
        isVerified: req.user.isVerified,
        name: req.user.name,
      },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    res.cookie('token', token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
    });
    res.redirect('/dashboard');
  }
);

app.use('/admin', authenticateAdmin);
app.use('/dashboard', authenticateToken);

app.get('/admin/tickets', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin/tickets.html'));
});

app.get('/dashboard/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/dashboard/profile.html'));
});

app.get('/dashboard/windows', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/dashboard/windows.html'));
});

// Chat Button Route
app.get('/chat', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/chat.html'));
});

// Dashboard Data API Route
app.get('/api/dashboard-data', authenticateAdmin, asyncHandler(async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const openTickets = await Ticket.countDocuments({ status: 'open' });
    const pendingTickets = await Ticket.countDocuments({ status: 'pending' });
    const guides = await Guide.countDocuments();

    const recentActivities = await Ticket.find().sort({ createdAt: -1 }).limit(10);

    res.json({
      totalUsers,
      openTickets,
      pendingTickets,
      guides,
      recentActivities: recentActivities.map(activity => ({
        description: activity.title,
        timestamp: activity.createdAt.toLocaleString(),
      })),
      chartData: {
        labels: ['January', 'February', 'March'],
        openTickets: [12, 19, 3],
        closedTickets: [5, 11, 8],
      },
    });
  } catch (error) {
    logger.error('Error fetching dashboard data:', error);
    res.status(500).json({ error: 'Error fetching dashboard data' });
  }
}));

// ==================== CRUD API for Guides ===================== //

// Get all guides
app.get('/apiguides', authenticateToken, asyncHandler(async (req, res) => {
  try {
    const guides = await Guide.find().sort({ createdAt: -1 });
    res.json({ guides });
  } catch (error) {
    logger.error('Error fetching guides:', error);
    res.status(500).json({ error: 'Error fetching guides' });
  }
}));

// Get guide by ID
app.get('/apiguides/id/:id', authenticateToken, asyncHandler(async (req, res) => {
  try {
    const guide = await Guide.findById(req.params.id);
    if (!guide) {
      return res.status(404).json({ error: 'Guide not found' });
    }
    res.json({ guide });
  } catch (error) {
    logger.error('Error fetching guide:', error);
    res.status(500).json({ error: 'Error fetching guide' });
  }
}));
