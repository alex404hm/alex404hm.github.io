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

// ============================= Configuration ============================== //
dotenv.config();

// Validate Required Environment Variables
const requiredEnvVars = [
  'BASE_URL',
  'PORT1',
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
  PORT1 = process.env.PORT1 || 3000,
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
          isVerified: true, 
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
  limits: { fileSize: 5 * 1024 * 1024 },
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
      isPremium: user.isPremium,
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

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: '❌ Too many requests, please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: '❌ Too many authentication attempts, please try again later.' },
});

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
app.use(generalLimiter);
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
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(['/api/login', '/api/signup'], authLimiter);

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
        maxAge: 24 * 60 * 60 * 1000,
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
app.get('/login', (req, res) => {
  res.redirect('/auth/login');
});
app.get('/signup', (req, res) => {
  res.redirect('/auth/signup');
});

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

app.get('/dashboard/profile', authenticateToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user.profileSetUp) {
    // Profile not set up yet, but user tries to access profile page
    // We'll just serve the page, which shows a message prompting setup.
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'profile.html'));
  logger.info(`Profile page served for user: ${req.user.email}`);
}));

// Admin Profile Page
app.get('/admin/profile', authenticateToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user || user.role !== 'admin') {
    return res.status(403).send("Forbidden: You are not an admin.");
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

// Complete Profile Setup
app.post('/api/user/setup', authenticateToken, asyncHandler(async (req, res) => {
  const { username, fullname, email } = req.body;
  // Validate fields as needed
  const user = await User.findById(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  // Mark profile as set up
  user.profileSetUp = true;
  // You can also save these details in the user model if you want
  user.name = fullname || user.name;
  user.email = email || user.email;
  await user.save();
  res.json({ message: "Profile has been successfully set up!" });
}));

// If user tries /auth and profileSetUp is false, redirect to setup
app.get('/auth', authenticateToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user.profileSetUp) {
    const token = uuidv4();
    return res.redirect(`/setup-profile?token=${token}`);
  }
  res.json({ message: "You are authenticated and your profile is set up!" });
}));

// (The rest of the code remains the same as given)

// User Registration Endpoint, Email Verification, Login, Logout
// Ticketing System, Guides API, etc. remain unchanged from original code.

// ========================= Existing API Endpoints & Error Handling ===============
// ... (All existing code related to Tickets, Guides, Admin endpoints, etc. remains unchanged)

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
server.listen(PORT1, () => {
  logger.info(`🚀 Server is running on PORT1 ${PORT1}`);
});
