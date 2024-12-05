// ========================= Import Dependencies ========================= //
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');
const asyncHandler = require('express-async-handler');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const { body, validationResult } = require('express-validator');
const multer = require('multer');

// ========================= Initialize Environment ========================= //
dotenv.config();

// ========================= Initialize Express App ========================= //
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ========================= Configuration ========================= //
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';
const SESSION_SECRET = process.env.SESSION_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_APP_PASSWORD = process.env.EMAIL_APP_PASSWORD;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const CORS_ORIGIN = process.env.CORS_ORIGIN || `http://localhost:${PORT}`;

// ========================= Logger Configuration ========================= //
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // Write all logs with level `info` and below to `server.log`
    new winston.transports.File({ filename: 'logs/server.log' }),
    // Write all logs to console
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

// ========================= Database Connection ========================= //
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => logger.info('🌟 Connected to MongoDB'))
.catch(err => {
  logger.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// ========================= Define Schemas and Models ========================= //

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, index: true },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String }, // Optional if using OAuth
  googleId: { type: String }, // For OAuth
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isVerified: { type: Boolean, default: false },
  profileSetup: { type: Boolean, default: false },
  sessionID: { type: String },
  ip: { type: String },
  userAgent: { type: String },
  forgotPasswordToken: { type: String },
  forgotPasswordTokenExpires: { type: Date },
  profileSetupToken: { type: String },
  profileSetupTokenExpires: { type: Date },
  avatar: { type: String }, // URL to profile picture
  phoneNumber: { type: String },
  bio: { type: String },
  theme: { type: String, enum: ['light', 'dark'], default: 'light' },
  lastLogin: { type: Date },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Guide Schema
const guideSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true },
  slug: { type: String, required: true },
  subtitle: { type: String },
  summary: { type: String },
  content: { type: String, required: true },
  tags: [{ type: String, index: true }],
  category: { type: String, required: true, index: true },
  bannerImage: { type: String },
  author: {
    id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    email: String,
  },
  publishDate: { type: String },
  views: { type: Number, default: 0, index: true },
}, { timestamps: true });

// Index for fast lookup of slug within category
guideSchema.index({ slug: 1, category: 1 }, { unique: true });

const Guide = mongoose.model('Guide', guideSchema);

// Ticket Schema
const ticketSchema = new mongoose.Schema({
  subject: { type: String, required: true },
  content: { type: String, required: true },
  status: { type: String, enum: ['open', 'closed'], default: 'open' },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

const Ticket = mongoose.model('Ticket', ticketSchema);

// Chat Message Schema
const chatMessageSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  message: { type: String, required: true },
  sender: { type: String, enum: ['user', 'admin', 'bot'], required: true },
  timestamp: { type: Date, default: Date.now },
}, { timestamps: true });

const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);

// ========================= Utility Functions ========================= //

/**
 * Generate JWT Token
 * @param {Object} user - User object
 * @param {String} expiresIn - Token expiration time
 * @returns {String} JWT Token
 */
const generateToken = (user, expiresIn = JWT_EXPIRES_IN) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
      isVerified: user.isVerified,
      name: user.name,
    },
    JWT_SECRET,
    { expiresIn }
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
  const verifyLink = `${BASE_URL}/verify-email?token=${token}`;

  const mailOptions = {
    from: `"No Reply" <${EMAIL_USER}>`,
    to: user.email,
    subject: '🔒 Verificer din emailadresse',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Hej ${user.name}!</h2>
        <p>Tak fordi du registrerede dig. Verificer venligst din emailadresse ved at klikke på linket nedenfor:</p>
        <a href="${verifyLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verificer Email</a>
        <p>Hvis du ikke har oprettet en konto, kan du ignorere denne email.</p>
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
    from: `"No Reply" <${EMAIL_USER}>`,
    to: user.email,
    subject: '🎉 Velkommen til Support Pro!',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Velkommen, ${user.name}!</h2>
        <p>Vi er glade for at have dig ombord. Udforsk vores funktioner og kontakt os, hvis du har spørgsmål.</p>
        <p>Med venlig hilsen,<br/>Support Pro Teamet</p>
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
 * Generate a unique slug within a category
 * @param {String} title - The title of the guide
 * @param {String} category - The category of the guide
 * @returns {String} - A unique slug
 */
const createUniqueSlug = async (title, category) => {
  let slug = generateSlug(title);
  let uniqueSlug = slug;
  let counter = 1;

  while (await Guide.findOne({ slug: uniqueSlug, category })) {
    uniqueSlug = `${slug}-${counter}`;
    counter++;
  }

  return uniqueSlug;
};

/**
 * Generate a unique token for password reset or profile setup
 * @returns {String} - Unique token
 */
const generateUniqueToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Function to get bot response using OpenAI's API
 * (Placeholder function - implement actual API call)
 */
const getBotResponse = async (userMessage) => {
  // TODO: Integrer med OpenAI's API for dynamiske svar
  // Eksempel implementering (kræver axios og OpenAI API-nøgle)
  /*
  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-3.5-turbo',
        messages: [{ role: 'user', content: userMessage }],
      },
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        },
      }
    );

    const botReply = response.data.choices[0].message.content.trim();
    return botReply;
  } catch (error) {
    logger.error('Error fetching bot response from OpenAI:', error);
    return '🤖 Undskyld, jeg kan ikke hjælpe i øjeblikket.';
  }
  */
  // For nu, returnere et statisk svar
  return `🧠 Du sagde: "${userMessage}". Hvordan kan jeg hjælpe dig yderligere?`;
};

// ======================== Nodemailer Configuration ====================== //
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_APP_PASSWORD,
  },
});

// ====================== Passport Configuration ========================== //

// Passport Configuration for Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
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
            user.isVerified = true; // Google OAuth provides verified email
            await user.save();
          }
          return done(null, user);
        }

        // If user doesn't exist, create new
        user = new User({
          googleId: profile.id,
          name: profile.displayName,
          email: email,
          isVerified: true, // Google OAuth provides verified email
          role: 'user',
          profileSetup: false,
        });
        await user.save();

        // Send Welcome Email
        await sendWelcomeEmail(user);

        // Generate profile setup token
        const profileSetupToken = generateUniqueToken();
        user.profileSetupToken = profileSetupToken;
        user.profileSetupTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        await user.save();

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

// ========================== Rate Limiting ============================ //

// Rate Limiter for API Routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requests per window per IP
  message: { error: '❌ For mange anmodninger, prøv igen senere.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate Limiter for Auth Routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Max 20 requests per window per IP
  message: { error: '❌ For mange loginforsøg, prøv igen senere.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ========================== Middleware Setup =========================== //

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true,
  })
);
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(helmet()); // Secure HTTP headers
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// ================== Session Configuration ==================
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      collectionName: 'sessions',
    }),
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

// ================== Authentication Middleware ================== //

/**
 * Middleware to check if the request is for an API route
 * @param {Object} req - Express request object
 * @returns {Boolean} - True if API route, else false
 */
const isApiRoute = (req) => req.path.startsWith('/api/');

/**
 * Authenticate JWT Token
 * For API routes: returns JSON errors
 * For Web routes: redirects to login pages
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) {
    logger.warn('Unauthorized access attempt.', { url: req.originalUrl });
    if (isApiRoute(req)) {
      return res.status(401).json({ error: '❌ Unauthorized access. Please log in.' });
    } else {
      // Determine redirect based on route
      if (req.path.startsWith('/admin')) {
        return res.redirect('/admin/login');
      } else {
        return res.redirect('/dashboard/login.html');
      }
    }
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      logger.warn('Invalid token provided.', { token });
      if (isApiRoute(req)) {
        return res.status(403).json({ error: '❌ Forbidden. Invalid token.' });
      } else {
        // Determine redirect based on route
        if (req.path.startsWith('/admin')) {
          return res.redirect('/admin/login');
        } else {
          return res.redirect('/dashboard/login.html');
        }
      }
    }
    req.user = decodedUser;
    next();
  });
};

/**
 * Authenticate Admin Users
 * Extends authenticateToken to check for admin role
 */
const authenticateAdmin = (req, res, next) => {
  authenticateToken(req, res, () => {
    if (req.user.role !== 'admin') {
      logger.warn('Admin access denied. Insufficient permissions.', { userRole: req.user.role });
      if (isApiRoute(req)) {
        return res.status(403).json({ error: '❌ Access Denied: Admins only.' });
      } else {
        return res.redirect('/admin/login');
      }
    }
    next();
  });
};

/**
 * Middleware to check if user's profile is set up
 */
const checkProfileSetup = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user.profileSetup) {
    if (isApiRoute(req)) {
      return res.status(200).json({
        message: '✅ Login successful. Please set up your profile.',
        redirect: '/auth/setup-profile.html',
      });
    } else {
      return res.redirect('/auth/setup-profile.html');
    }
  }
  next();
});

/**
 * Middleware to ensure authenticated and profile is set up
 * Used for frontend redirection
 */
const ensureAuthenticatedAndSetup = asyncHandler(async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/auth/login');
  }

  jwt.verify(token, JWT_SECRET, async (err, decodedUser) => {
    if (err) {
      return res.redirect('/auth/login');
    }
    req.user = decodedUser;
    const user = await User.findById(req.user.id);
    if (!user.profileSetup) {
      return res.redirect('/auth/setup-profile.html');
    }
    next();
  });
});

// ========================== Multer Configuration ====================== //

// Create 'uploads' directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure Multer Storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    // Generate unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    // Extract file extension
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  },
});

// File Filter to accept only images
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif/;
  const ext = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mime = allowedTypes.test(file.mimetype);
  if (ext && mime) {
    return cb(null, true);
  } else {
    cb(new Error('❌ Kun JPEG, PNG, og GIF billeder er tilladt.'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: fileFilter,
});

// ========================== Route Definitions ============================ //

/**
 * Function to set up routes
 */
const setupRoutes = () => {
  const definedRoutes = [
    {
      route: '/auth',
      file: path.join(__dirname, 'public', 'auth', 'auth.html'),
      redirectIfAuthenticated: true,
    },
    {
      route: '/auth/login',
      file: path.join(__dirname, 'public', 'auth', 'login.html'),
      redirectIfAuthenticated: true,
    },
    {
      route: '/auth/signup',
      file: path.join(__dirname, 'public', 'auth', 'signup.html'),
      redirectIfAuthenticated: true,
    },
    {
      route: '/auth/setup-profile.html',
      file: path.join(__dirname, 'public', 'auth', 'setup-profile.html'),
      requiresAuth: true,
      requiresProfileSetup: false, // Only users who haven't set up profile
    },
    {
      route: '/dashboard',
      file: path.join(__dirname, 'public', 'dashboard', 'dashboard.html'),
      requiresAuth: true,
      extraMiddlewares: [checkProfileSetup],
    },
    {
      route: '/dashboard/login.html',
      file: path.join(__dirname, 'public', 'dashboard', 'login.html'),
      redirectIfAuthenticated: true,
    },
    {
      route: '/admin',
      file: path.join(__dirname, 'public', 'admin', '/admin'),
      requiresAuth: true,
      requiresAdmin: true,
    },
    {
      route: '/admin/login',
      file: path.join(__dirname, 'public', 'admin', 'login.html'),
      redirectIfAuthenticated: true,
    },
    {
      route: '/dashboard/profile',
      file: path.join(__dirname, 'public', 'dashboard', 'profile.html'),
      requiresAuth: true,
      extraMiddlewares: [checkProfileSetup],
    },
    // Add more routes as needed
  ];

  definedRoutes.forEach(
    ({
      route,
      file,
      redirectIfAuthenticated,
      requiresAuth,
      requiresAdmin,
      requiresProfileSetup,
      extraMiddlewares,
    }) => {
      if (redirectIfAuthenticated) {
        app.get(
          route,
          asyncHandler(async (req, res, next) => {
            const token = req.cookies.token;
            if (token) {
              try {
                const decoded = jwt.verify(token, JWT_SECRET);
                // Redirect to dashboard if already logged in
                return res.redirect(
                  route.includes('login') || route.includes('signup') ? '/dashboard' : '/'
                );
              } catch (err) {
                // Invalid token, proceed to serve the page
              }
            }
            next();
          }),
          (req, res) => {
            res.sendFile(file);
          }
        );
      } else if (requiresAuth) {
        // Build middleware array dynamically to avoid passing null
        const middlewares = [authenticateToken];
        if (requiresAdmin) {
          middlewares.push(authenticateAdmin);
        }
        if (extraMiddlewares && Array.isArray(extraMiddlewares)) {
          middlewares.push(...extraMiddlewares);
        }
        if (requiresProfileSetup === false) {
          // For setup-profile.html, ensure profile is not set up
          middlewares.push(asyncHandler(async (req, res, next) => {
            const user = await User.findById(req.user.id);
            if (user.profileSetup) {
              return res.redirect('/dashboard');
            }
            next();
          }));
        }
        app.get(route, ...middlewares, (req, res) => {
          res.sendFile(file);
        });
      } else {
        app.get(route, (req, res) => {
          res.sendFile(file);
        });
      }
    }
  );
};

// Initialize routes
setupRoutes();

/**
 * Dynamic Dashboard OS Routes
 */
const allowedOS = ['windows', 'macos', 'linux', 'ios', 'android', 'chromeos'];

app.get(
  '/dashboard/:os',
  authenticateToken,
  checkProfileSetup,
  asyncHandler(async (req, res) => {
    const osParam = req.params.os.toLowerCase();

    if (!allowedOS.includes(osParam)) {
      logger.warn('Dashboard OS route accessed with invalid OS.', { os: osParam });
      if (isApiRoute(req)) {
        return res.status(404).json({ error: '❌ Not found' });
      } else {
        return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }
    }

    const osFile = path.join(__dirname, 'public', 'dashboard', `${osParam}.html`);
    if (fs.existsSync(osFile)) {
      res.sendFile(osFile);
    } else {
      logger.warn('Dashboard OS file not found.', { os: osParam, osFile });
      if (isApiRoute(req)) {
        return res.status(404).json({ error: '❌ Not found' });
      } else {
        res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }
    }
  })
);

/**
 * Dynamic Admin Panel Section Routes
 */
const allowedAdminSections = ['tickets', 'guides', 'logs', 'users'];

app.get(
  '/admin/:section',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    const sectionParam = req.params.section.toLowerCase();

    if (!allowedAdminSections.includes(sectionParam)) {
      logger.warn('Admin section route accessed with invalid section.', { section: sectionParam });
      if (isApiRoute(req)) {
        return res.status(404).json({ error: '❌ Not found' });
      } else {
        return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }
    }

    const sectionFile = path.join(__dirname, 'public', 'admin', `${sectionParam}.html`);
    if (fs.existsSync(sectionFile)) {
      res.sendFile(sectionFile);
    } else {
      logger.warn('Admin section file not found.', { section: sectionParam, sectionFile });
      if (isApiRoute(req)) {
        return res.status(404).json({ error: '❌ Not found' });
      } else {
        res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }
    }
  })
);

/**
 * OAuth Routes
 */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/login' }),
  asyncHandler(async (req, res) => {
    // Successful authentication, generate JWT token and set cookie
    const token = generateToken(req.user);
    res.cookie('token', token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    // Set additional cookies: sessionID, email, IP, User-Agent
    const sessionID = generateSessionID();
    req.user.sessionID = sessionID;
    await req.user.save();

    res.cookie('sessionID', sessionID, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.cookie('email', req.user.email, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.cookie('ip', req.ip, {
      httpOnly: false, // Accessible via client-side
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.cookie('userAgent', req.get('User-Agent'), {
      httpOnly: false, // Accessible via client-side
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    // Check if profile is set up
    if (!req.user.profileSetup) {
      return res.redirect(`/auth/setup-profile.html?token=${req.user.profileSetupToken}`);
    }

    res.redirect('/dashboard');
  })
);

/**
 * Cookie Consent Endpoint
 */
app.post(
  '/api/cookies/accept',
  asyncHandler(async (req, res) => {
    try {
      res.cookie('cookiesAccepted', 'true', {
        httpOnly: false, // Accessible via client-side
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      });
      res.status(200).json({ message: '✅ Cookies accepteret.' });
    } catch (error) {
      logger.error('Error accepting cookies:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

/**
 * User Registration Endpoint
 */
app.post(
  '/api/signup',
  authLimiter,
  [
    body('name').trim().notEmpty().withMessage('Navn er påkrævet.').escape(),
    body('email').isEmail().withMessage('Gyldig email er påkrævet.').normalizeEmail(),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password skal være mindst 6 tegn lang.')
      .escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Signup failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      const existingUser = await User.findOne({ email });

      if (existingUser && existingUser.password) {
        logger.warn('Signup failed: User already exists.', { email });
        return res.status(400).json({ error: '❌ Bruger eksisterer allerede med denne email.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const sessionID = generateSessionID();
      const profileSetupToken = generateUniqueToken();
      const profileSetupTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

      let user;
      if (existingUser) {
        existingUser.password = hashedPassword;
        existingUser.sessionID = sessionID;
        existingUser.name = name; // Update name if provided
        existingUser.profileSetupToken = profileSetupToken;
        existingUser.profileSetupTokenExpires = profileSetupTokenExpires;
        user = await existingUser.save();
      } else {
        user = new User({
          name,
          email,
          password: hashedPassword,
          sessionID,
          role: 'user',
          profileSetupToken,
          profileSetupTokenExpires,
        });
        await user.save();
      }

      // Send profile setup email with unique URL
      const setupProfileLink = `${BASE_URL}/auth/setup-profile.html?token=${profileSetupToken}`;
      const mailOptions = {
        from: `"No Reply" <${EMAIL_USER}>`,
        to: user.email,
        subject: '🔑 Fuldfør din Profilopsætning',
        html: `
          <div style="font-family: Arial, sans-serif;">
            <h2>Hej, ${user.name}!</h2>
            <p>Tak for din registrering. Fuldfør venligst din profilopsætning ved at klikke på linket nedenfor:</p>
            <a href="${setupProfileLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Fuldfør Profilopsætning</a>
            <p>Denne link er gyldig i 24 timer og kan kun bruges én gang.</p>
            <p>Hvis du ikke har oprettet en konto, kan du ignorere denne email.</p>
          </div>
        `,
      };

      await transporter.sendMail(mailOptions);

      logger.info(`User registered: ${email}`, { userId: user._id });
      res.status(201).json({
        message: '✅ Bruger registreret. Tjek din email for at fuldføre profilopsætningen.',
      });
    } catch (err) {
      if (err.code === 11000) {
        logger.error('Signup error: Duplicate email.', { email });
        res.status(400).json({ error: '❌ Email allerede i brug.' });
      } else {
        logger.error('Signup error:', err);
        res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
      }
    }
  })
);

/**
 * Login Endpoint
 */
app.post(
  '/api/login',
  authLimiter,
  [
    body('email').isEmail().withMessage('Gyldig email er påkrævet.').normalizeEmail(),
    body('password').notEmpty().withMessage('Password er påkrævet.').escape(),
    body('rememberMe').optional().isBoolean(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, rememberMe } = req.body;

    try {
      const user = await User.findOne({ email });

      if (!user || !user.password) {
        logger.warn('Login failed: User does not exist.', { email });
        return res.status(404).json({ error: '❌ Bruger findes ikke. Venligst opret en konto.' });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        logger.warn('Login failed: Invalid credentials.', { email });
        return res.status(401).json({ error: '❌ Ugyldige loginoplysninger.' });
      }

      if (!user.isVerified) {
        logger.warn('Login failed: Email not verified.', { email });
        // Redirect to verify page instead of returning JSON error
        return res.status(403).json({
          message: '❌ Verificer din email for at få adgang.',
          redirect: '/verify.html', // Assuming verify.html exists in public
        });
      }

      // Set token expiration based on rememberMe
      const tokenExpiry = rememberMe ? '7d' : JWT_EXPIRES_IN;

      const token = generateToken(user, tokenExpiry);
      const sessionID = generateSessionID();
      user.sessionID = sessionID;
      user.lastLogin = new Date();
      user.ip = req.ip;
      user.userAgent = req.get('User-Agent');
      await user.save();

      // Set cookies
      res.cookie('token', token, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 7 days or 1 day
      });

      res.cookie('sessionID', sessionID, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
      });

      res.cookie('email', user.email, {
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
      });

      res.cookie('ip', req.ip, {
        httpOnly: false, // Accessible via client-side
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
      });

      res.cookie('userAgent', req.get('User-Agent'), {
        httpOnly: false, // Accessible via client-side
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
      });

      logger.info(`User logged in: ${email}`, { userId: user._id });

      // Check if profile is set up
      if (!user.profileSetup) {
        return res.status(200).json({
          message: '✅ Login successful. Venligst fuldfør din profilopsætning.',
          redirect: '/auth/setup-profile.html',
        });
      }

      res.status(200).json({
        message: '✅ Login successful.',
        redirect: '/dashboard',
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
      res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
    }
  })
);

/**
 * Logout Endpoint
 */
app.post(
  '/api/logout',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const user = await User.findById(req.user.id);
      if (user) {
        user.sessionID = null;
        await user.save();
      }

      // Clear all relevant cookies
      res.clearCookie('token', {
        path: '/',
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
      });
      res.clearCookie('sessionID', {
        path: '/',
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
      });
      res.clearCookie('email', {
        path: '/',
        httpOnly: true,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
      });
      res.clearCookie('ip', {
        path: '/',
        httpOnly: false,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
      });
      res.clearCookie('userAgent', {
        path: '/',
        httpOnly: false,
        secure: NODE_ENV === 'production',
        sameSite: 'strict',
      });

      logger.info(`User logged out: ${req.user.email}`, { userId: req.user.id });
      res.status(200).json({ message: '✅ Logout successful.' });
    } catch (error) {
      logger.error('Logout error:', error);
      res.status(500).json({ error: '❌ Serverfejl under logout.' });
    }
  })
);

/**
 * Verify Email Endpoint
 */
app.get(
  '/verify-email',
  asyncHandler(async (req, res) => {
    const token = req.query.token;

    if (!token) {
      return res.status(400).sendFile(path.join(__dirname, 'public', 'error', '400.html'));
    }

    jwt.verify(token, JWT_SECRET, async (err, decodedUser) => {
      if (err) {
        logger.warn('Email verification failed: Invalid token.', { token });
        return res.status(400).sendFile(path.join(__dirname, 'public', 'error', '400.html'));
      }

      try {
        const user = await User.findById(decodedUser.id);

        if (!user) {
          return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
        }

        if (user.isVerified) {
          return res.redirect('/dashboard');
        }

        user.isVerified = true;
        await user.save();

        logger.info(`User verified: ${user.email}`, { userId: user._id });
        res.redirect('/dashboard');
      } catch (error) {
        logger.error('Email verification error:', error);
        res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
      }
    });
  })
);

/**
 * Resend Verification Email Endpoint
 */
app.post(
  '/api/resend-verification',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const user = await User.findById(req.user.id);

      if (!user) {
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }

      if (user.isVerified) {
        return res.status(400).json({ error: '❌ Email er allerede verificeret.' });
      }

      // Generate new verification token
      const token = generateToken(user, '1h'); // Token gyldig i 1 time

      // Send verification email
      await sendVerificationEmail(user, token);

      logger.info(`Verification email resent to: ${user.email}`, { userId: user._id });
      res.status(200).json({ message: '✅ Verifikationsmail sendt igen.' });
    } catch (error) {
      logger.error('Error resending verification email:', error);
      res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
    }
  })
);

/**
 * Forgot Password Request
 */
app.post(
  '/api/password-reset/request',
  authLimiter,
  [
    body('email').isEmail().withMessage('Gyldig email er påkrævet.').normalizeEmail(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Password reset request failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }

      // Generate password reset token
      const resetToken = generateUniqueToken();
      const resetTokenExpires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

      user.forgotPasswordToken = resetToken;
      user.forgotPasswordTokenExpires = resetTokenExpires;
      await user.save();

      const resetLink = `${BASE_URL}/password-reset.html?token=${resetToken}`;

      const mailOptions = {
        from: `"No Reply" <${EMAIL_USER}>`,
        to: user.email,
        subject: '🔑 Anmodning om Password Reset',
        html: `
          <div style="font-family: Arial, sans-serif;">
            <h2>Hej, ${user.name}!</h2>
            <p>Du har anmodet om at nulstille din adgangskode. Klik på linket nedenfor for at fortsætte:</p>
            <a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Nulstil Adgangskode</a>
            <p>Denne link vil udløbe om 1 time. Hvis du ikke anmodede om dette, kan du ignorere denne email.</p>
          </div>
        `,
      };

      await transporter.sendMail(mailOptions);

      logger.info(`Password reset email sent to: ${email}`, { userId: user._id });
      res.status(200).json({ message: '✅ Password reset email sendt.' });
    } catch (error) {
      logger.error('Error sending password reset email:', error);
      res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
    }
  })
);

/**
 * Confirm Password Reset
 */
app.post(
  '/api/password-reset/confirm',
  [
    body('token').notEmpty().withMessage('Token er påkrævet.').trim(),
    body('newPassword')
      .isLength({ min: 6 })
      .withMessage('Password skal være mindst 6 tegn lang.')
      .escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Password reset confirm failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { token, newPassword } = req.body;

    try {
      const user = await User.findOne({
        forgotPasswordToken: token,
        forgotPasswordTokenExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({ error: '❌ Ugyldig eller udløbet token.' });
      }

      user.password = await bcrypt.hash(newPassword, 10);
      user.forgotPasswordToken = undefined;
      user.forgotPasswordTokenExpires = undefined;
      await user.save();

      logger.info(`Password reset successfully for user: ${user.email}`, { userId: user._id });
      res.status(200).json({ message: '✅ Adgangskode nulstillet.' });
    } catch (error) {
      logger.error('Error resetting password:', error);
      res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
    }
  })
);

/**
 * Forgot Email (Placeholder - Implement as needed)
 * 
 * Denne funktionalitet er ikke standard, men kan implementeres ved at søge brugeren baseret på andre oplysninger.
 */
app.post(
  '/api/forgot-email',
  [
    body('name').trim().notEmpty().withMessage('Navn er påkrævet.').escape(),
    body('phoneNumber')
      .trim()
      .notEmpty()
      .withMessage('Telefonnummer er påkrævet.')
      .matches(/^[0-9+\-()\s]+$/)
      .withMessage('Ugyldigt telefonnummerformat.')
      .escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Forgot email request failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, phoneNumber } = req.body;

    try {
      // Find user by name and phone number
      const user = await User.findOne({ name, phoneNumber });

      if (!user) {
        return res.status(404).json({ error: '❌ Bruger ikke fundet med de angivne oplysninger.' });
      }

      // Send email to the user with their registered email
      const mailOptions = {
        from: `"No Reply" <${EMAIL_USER}>`,
        to: user.email,
        subject: '📧 Din Registrerede Emailadresse',
        html: `
          <div style="font-family: Arial, sans-serif;">
            <h2>Hej, ${user.name}!</h2>
            <p>Din registrerede emailadresse er: <strong>${user.email}</strong></p>
            <p>Hvis du ikke anmodede om dette, bedes du kontakte vores supportteam.</p>
          </div>
        `,
      };

      await transporter.sendMail(mailOptions);

      logger.info(`Forgot email information sent to: ${user.email}`, { userId: user._id });
      res.status(200).json({ message: '✅ Din registrerede emailadresse er sendt til din email.' });
    } catch (error) {
      logger.error('Error handling forgot email request:', error);
      res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
    }
  })
);

/**
 * Profile Setup Endpoint with Image Upload and One-Time Token Validation
 */
app.get(
  '/auth/setup-profile.html',
  asyncHandler(async (req, res) => {
    const token = req.query.token;

    if (!token) {
      return res.status(400).sendFile(path.join(__dirname, 'public', 'error', '400.html'));
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        logger.warn('Profile setup failed: Invalid token.', { token });
        return res.status(400).sendFile(path.join(__dirname, 'public', 'error', '400.html'));
      }

      try {
        const user = await User.findById(decoded.id);

        if (!user) {
          return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
        }

        if (user.profileSetup) {
          return res.redirect('/dashboard');
        }

        if (
          user.profileSetupToken !== token ||
          user.profileSetupTokenExpires < Date.now()
        ) {
          return res.status(400).sendFile(path.join(__dirname, 'public', 'error', '400.html'));
        }

        // Token is valid, render setup-profile.html
        res.sendFile(path.join(__dirname, 'public', 'auth', 'setup-profile.html'));
      } catch (error) {
        logger.error('Profile setup validation error:', error);
        res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
      }
    });
  })
);

/**
 * Handle Profile Setup Submission
 */
app.post(
  '/api/profile/setup',
  authenticateToken,
  upload.single('profilePicture'), // Handle 'profilePicture' field
  [
    body('fullName').trim().notEmpty().withMessage('Fuldt navn er påkrævet.').escape(),
    body('phoneNumber')
      .trim()
      .notEmpty()
      .withMessage('Telefonnummer er påkrævet.')
      .matches(/^[0-9+\-()\s]+$/)
      .withMessage('Ugyldigt telefonnummerformat.')
      .escape(),
    body('token').notEmpty().withMessage('Token er påkrævet.').escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    const profilePicture = req.file;
    const token = req.body.token; // Assume token is sent as part of the form data

    if (!errors.isEmpty()) {
      // If using multer, file is handled separately
      if (profilePicture) {
        fs.unlinkSync(profilePicture.path);
      }
      logger.warn('Profile setup failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    if (!token) {
      if (profilePicture) {
        fs.unlinkSync(profilePicture.path);
      }
      return res.status(400).json({ error: '❌ Manglende profilopsætnings-token.' });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);

      if (!user) {
        if (profilePicture) {
          fs.unlinkSync(profilePicture.path);
        }
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }

      if (user.profileSetup) {
        if (profilePicture) {
          fs.unlinkSync(profilePicture.path);
        }
        return res.redirect('/dashboard');
      }

      if (
        user.profileSetupToken !== token ||
        user.profileSetupTokenExpires < Date.now()
      ) {
        if (profilePicture) {
          fs.unlinkSync(profilePicture.path);
        }
        return res.status(400).json({ error: '❌ Ugyldig eller udløbet profilopsætnings-token.' });
      }

      const { fullName, phoneNumber } = req.body;

      // If a new profile picture is uploaded, remove the old one if it exists
      if (profilePicture) {
        if (user.avatar) {
          const oldAvatarPath = path.join(__dirname, 'public', user.avatar);
          if (fs.existsSync(oldAvatarPath)) {
            fs.unlinkSync(oldAvatarPath);
          }
        }
        user.avatar = `/uploads/${profilePicture.filename}`;
      }

      // Update full name and phone number
      user.name = fullName;
      user.phoneNumber = phoneNumber;
      user.profileSetup = true;
      user.profileSetupToken = undefined;
      user.profileSetupTokenExpires = undefined;
      await user.save();

      logger.info(`User profile setup completed: ${user.email}`, { userId: user._id });

      // Redirect to dashboard after successful profile setup
      res.status(200).json({
        message: '✅ Profilopsætning fuldført.',
        redirect: '/dashboard',
      });
    } catch (error) {
      if (profilePicture) {
        fs.unlinkSync(profilePicture.path);
      }
      logger.error('Error setting up profile:', error);
      res.status(500).json({ error: '❌ Serverfejl. Prøv igen senere.' });
    }
  })
);

/**
 * Landing Page Route
 * Redirect to /dashboard if authenticated, else to /auth
 */
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
      if (!err) {
        return res.redirect('/dashboard');
      }
      res.redirect('/auth');
    });
  } else {
    res.redirect('/auth');
  }
});

/**
 * Serve Error Pages
 */
const errorStatuses = [400, 401, 403, 404, 408, 429, 500, 502, 503, 504];

errorStatuses.forEach(status => {
  app.get(`/error/${status}.html`, (req, res) => {
    res.status(status).sendFile(path.join(__dirname, 'public', 'error', `${status}.html`));
  });
});

/**
 * Handle 404 for undefined routes
 */
app.use((req, res, next) => {
  if (isApiRoute(req)) {
    return res.status(404).json({ error: '❌ Ikke fundet' });
  } else {
    return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
  }
});

/**
 * General Error Handler
 */
app.use((err, req, res, next) => {
  logger.error('❌ Server Error:', err.stack);
  const status = err.status || 500;
  if (errorStatuses.includes(status)) {
    if (isApiRoute(req)) {
      res.status(status).json({ error: `❌ ${status} Server Error` });
    } else {
      res.status(status).sendFile(path.join(__dirname, 'public', 'error', `${status}.html`));
    }
  } else {
    if (isApiRoute(req)) {
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    } else {
      res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
    }
  }
});

// ========================= API Endpoints ========================= //

/**
 * Users API
 */
app.get(
  '/api/users',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const users = await User.find().select('-password').sort({ createdAt: -1 });
      res.json({ users });
    } catch (error) {
      logger.error('Error fetching users:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

app.post(
  '/api/users',
  authenticateAdmin,
  [
    express.json(),
    express.urlencoded({ extended: true }),
    body('name').trim().notEmpty().withMessage('Navn er påkrævet.').escape(),
    body('email').isEmail().withMessage('Gyldig email er påkrævet.').normalizeEmail(),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password skal være mindst 6 tegn lang.')
      .escape(),
    body('role').isIn(['user', 'admin']).withMessage('Rolle skal være user eller admin.').escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Create user failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, role } = req.body;

    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        logger.warn('Create user failed: Email already in use.', { email });
        return res.status(400).json({ error: '❌ Email allerede i brug.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = new User({
        name,
        email,
        password: hashedPassword,
        role,
        isVerified: true, // Assuming admin is creating verified users
        profileSetup: false,
      });

      await user.save();
      logger.info('User created:', { email, userId: user._id });
      res.status(201).json({ message: '✅ Bruger oprettet.' });
    } catch (error) {
      logger.error('Create user failed:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

app.put(
  '/api/users/:id',
  authenticateAdmin,
  [
    express.json(),
    express.urlencoded({ extended: true }),
    body('name').optional().trim().notEmpty().withMessage('Navn kan ikke være tomt.').escape(),
    body('email').optional().isEmail().withMessage('Gyldig email er påkrævet.').normalizeEmail(),
    body('password')
      .optional()
      .isLength({ min: 6 })
      .withMessage('Password skal være mindst 6 tegn lang.')
      .escape(),
    body('role').optional().isIn(['user', 'admin']).withMessage('Rolle skal være user eller admin.').escape(),
    body('status').optional().isIn(['active', 'inactive']).withMessage('Status skal være active eller inactive.').escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Update user failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, role, status } = req.body;
    const updateData = {};

    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (role) updateData.role = role;
    if (status) updateData.status = status;
    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    try {
      const user = await User.findByIdAndUpdate(req.params.id, updateData, {
        new: true,
        runValidators: true,
      });

      if (!user) {
        logger.warn('Update user failed: User not found.', { userId: req.params.id });
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }

      logger.info('User updated:', { email: user.email, userId: user._id });
      res.json({ message: '✅ Bruger opdateret.' });
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Update user failed: Duplicate email.', { email: req.body.email });
        res.status(400).json({ error: '❌ Email allerede i brug.' });
      } else {
        logger.error('Update user failed:', error);
        res.status(500).json({ error: '❌ Internt serverfejl.' });
      }
    }
  })
);

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
        logger.warn('Deactivate user failed: User not found.', { userId: req.params.id });
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }

      logger.info('User deactivated:', { email: user.email, userId: user._id });
      res.json({ message: '✅ Bruger deaktiveret.' });
    } catch (error) {
      logger.error('Deactivate user failed:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

// ========================= Guides API ========================= //

/**
 * Get Popular Guides Sorted by Views
 */
app.get(
  '/apiguides/popular',
  asyncHandler(async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 6;
      const popularGuides = await Guide.find().sort({ views: -1 }).limit(limit);
      res.json({ guides: popularGuides });
    } catch (error) {
      logger.error('Error fetching popular guides:', error);
      res.status(500).json({ error: '❌ Fejl ved hentning af populære guider.' });
    }
  })
);

/**
 * Fetch a Guide by Category and Slug
 */
app.get(
  '/apiguides/:category/:slug',
  asyncHandler(async (req, res) => {
    try {
      const { category, slug } = req.params;
      const guide = await Guide.findOne({
        category: new RegExp(`^${category}$`, 'i'),
        slug: new RegExp(`^${slug}$`, 'i'),
      });
      if (!guide) {
        return res.status(404).json({ error: '❌ Guide ikke fundet.' });
      }
      res.json(guide);
    } catch (error) {
      logger.error('Error fetching guide by category and slug:', { error, params: req.params });
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

/**
 * Fetch a Single Guide by ID
 */
app.get(
  '/apiguides/id/:id',
  asyncHandler(async (req, res) => {
    try {
      const guide = await Guide.findById(req.params.id);
      if (!guide) {
        return res.status(404).json({ error: '❌ Guide ikke fundet.' });
      }
      res.json(guide);
    } catch (error) {
      logger.error('Error fetching guide:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

/**
 * Fetch All Guides with Optional Filtering
 */
app.get(
  '/apiguides',
  asyncHandler(async (req, res) => {
    try {
      const { category, tag, search, page = 1, limit = 10 } = req.query;
      let query = {};

      if (category) query.category = new RegExp(category, 'i');
      if (tag) query.tags = new RegExp(tag, 'i');
      if (search) {
        query.$or = [
          { title: new RegExp(search, 'i') },
          { summary: new RegExp(search, 'i') },
          { content: new RegExp(search, 'i') },
        ];
      }

      const guides = await Guide.find(query)
        .skip((page - 1) * limit)
        .limit(parseInt(limit))
        .sort({ createdAt: -1 });

      res.json({ guides });
    } catch (error) {
      logger.error('Error fetching guides:', error);
      res.status(500).json({ error: '❌ Fejl ved hentning af guider.' });
    }
  })
);

/**
 * Search API for Guides
 * Example: /apiguides/search?q=searchTerm
 */
app.get(
  '/apiguides/search',
  asyncHandler(async (req, res) => {
    const query = req.query.q;
    if (!query) {
      return res.status(400).json({ error: '❌ Query parameter er påkrævet.' });
    }

    try {
      const results = await Guide.find({
        $or: [
          { title: { $regex: query, $options: 'i' } },
          { summary: { $regex: query, $options: 'i' } },
          { content: { $regex: query, $options: 'i' } },
        ],
      });

      res.json({ guides: results });
    } catch (error) {
      logger.error('Error searching guides:', error);
      res.status(500).json({ error: '❌ Fejl ved søgning af guider.' });
    }
  })
);

/**
 * Create a New Guide (Authenticated Users)
 */
app.post(
  '/apiguides',
  authenticateToken,
  [
    body('title').trim().notEmpty().withMessage('Titel er påkrævet.').escape(),
    body('subtitle').optional().trim().escape(),
    body('summary').optional().trim().escape(),
    body('content').trim().notEmpty().withMessage('Indhold er påkrævet.').escape(),
    body('tags').optional().isArray().withMessage('Tags skal være en array.'),
    body('tags.*').optional().trim().escape(),
    body('category').trim().notEmpty().withMessage('Kategori er påkrævet.').escape(),
    body('bannerImage').optional().trim().escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Create guide failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, subtitle, summary, content, tags, category, bannerImage } = req.body;

    try {
      // Generate a unique slug within the category
      const uniqueSlug = await createUniqueSlug(title, category);

      const newGuide = new Guide({
        title,
        slug: uniqueSlug,
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
      logger.info(`Guide created: ${title} by ${req.user.email}`, { guideId: savedGuide._id, userId: req.user.id });
      res.status(201).json(savedGuide);
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Create guide failed: Duplicate slug and category.', { title, category });
        res.status(400).json({ error: '❌ En guide med samme titel og kategori eksisterer allerede.' });
      } else {
        logger.error('Create guide failed:', error);
        res.status(500).json({ error: '❌ Fejl ved oprettelse af guide.' });
      }
    }
  })
);

/**
 * Update an Existing Guide (Authenticated Users)
 */
app.put(
  '/apiguides/id/:id',
  authenticateToken,
  [
    body('title').optional().trim().notEmpty().withMessage('Titel kan ikke være tomt.').escape(),
    body('subtitle').optional().trim().escape(),
    body('summary').optional().trim().escape(),
    body('content').optional().trim().notEmpty().withMessage('Indhold kan ikke være tomt.').escape(),
    body('tags').optional().isArray().withMessage('Tags skal være en array.'),
    body('tags.*').optional().trim().escape(),
    body('category').optional().trim().notEmpty().withMessage('Kategori kan ikke være tomt.').escape(),
    body('bannerImage').optional().trim().escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Update guide failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, content, category, subtitle, summary, tags, bannerImage } = req.body;
    const updates = {};

    if (title) updates.title = title;
    if (subtitle) updates.subtitle = subtitle;
    if (summary) updates.summary = summary;
    if (content) updates.content = content;
    if (tags) updates.tags = tags;
    if (category) updates.category = category;
    if (bannerImage) updates.bannerImage = bannerImage;

    try {
      if (title || category) {
        // Need to generate a unique slug within the new or existing category
        const currentGuide = await Guide.findById(req.params.id);
        if (!currentGuide) {
          return res.status(404).json({ error: '❌ Guide ikke fundet.' });
        }
        const newTitle = title || currentGuide.title;
        const newCategory = category || currentGuide.category;
        updates.slug = await createUniqueSlug(newTitle, newCategory);
      }

      const updatedGuide = await Guide.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
      if (!updatedGuide) {
        logger.warn('Update guide failed: Guide not found.', { guideId: req.params.id });
        return res.status(404).json({ error: '❌ Guide ikke fundet.' });
      }
      logger.info(`Guide updated: ${updatedGuide.title} by ${req.user.email}`, { guideId: updatedGuide._id, userId: req.user.id });
      res.json(updatedGuide);
    } catch (error) {
      if (error.code === 11000) {
        logger.error('Update guide failed: Duplicate slug and category.', { title, category });
        res.status(400).json({ error: '❌ En guide med samme titel og kategori eksisterer allerede.' });
      } else {
        logger.error('Update guide failed:', error);
        res.status(500).json({ error: '❌ Fejl ved opdatering af guide.' });
      }
    }
  })
);

/**
 * Delete a Guide by ID (Authenticated Users)
 */
app.delete(
  '/apiguides/id/:id',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const deletedGuide = await Guide.findByIdAndDelete(req.params.id);
      if (!deletedGuide) {
        logger.warn('Delete guide failed: Guide not found.', { guideId: req.params.id });
        return res.status(404).json({ error: '❌ Guide ikke fundet.' });
      }
      logger.info(`Guide deleted: ${deletedGuide.title} by ${req.user.email}`, { guideId: deletedGuide._id, userId: req.user.id });
      res.json({ message: '✅ Guide slettet.' });
    } catch (error) {
      logger.error('Delete guide failed:', error);
      res.status(500).json({ error: '❌ Fejl ved sletning af guide.' });
    }
  })
);

/**
 * Serve the Guide Page Based on Category and Slug
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
        return res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
      }

      // Increment the view count
      guide.views += 1;
      await guide.save();

      // Serve the guide template with dynamic data (Assuming your frontend handles it)
      res.sendFile(path.join(__dirname, 'public', 'template.html'));
    } catch (error) {
      logger.error('Serve guide failed:', { error, params: req.params });
      res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
    }
  })
);

// ==================== Chatbot and Real-time Chat ================== //

/**
 * Chat Routes
 */

/**
 * Get Chat History (Authenticated Users)
 */
app.get(
  '/api/chat/history',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const messages = await ChatMessage.find({ user: req.user.id }).sort({ timestamp: 1 });
      res.json({ messages });
    } catch (error) {
      logger.error('Error fetching chat history:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

/**
 * Send Chat Message (Authenticated Users)
 */
app.post(
  '/api/chat/message',
  authenticateToken,
  [
    body('message').trim().notEmpty().withMessage('Besked er påkrævet.').escape(),
    body('recipientType')
      .trim()
      .notEmpty()
      .withMessage('Recipient type er påkrævet.')
      .isIn(['bot', 'admin'])
      .withMessage('Recipient type skal være bot eller admin.')
      .escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Send chat message failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { message, recipientType } = req.body;

    try {
      const newMessage = new ChatMessage({
        user: req.user.id,
        message,
        sender: 'user',
      });
      await newMessage.save();

      // Emit message via Socket.IO
      io.to(req.user.id.toString()).emit('chat message', {
        sender: 'user',
        message,
        timestamp: newMessage.timestamp,
      });

      // Handle bot response if recipientType is 'bot'
      if (recipientType === 'bot') {
        const botResponse = await getBotResponse(message);

        const botMessage = new ChatMessage({
          user: req.user.id,
          message: botResponse,
          sender: 'bot',
        });
        await botMessage.save();

        // Emit bot response via Socket.IO
        io.to(req.user.id.toString()).emit('chat message', {
          sender: 'bot',
          message: botResponse,
          timestamp: botMessage.timestamp,
        });

        res.status(200).json({ message: '✅ Besked sendt og bot svar modtaget.' });
      } else if (recipientType === 'admin') {
        // Placeholder for real admin chat implementation
        res.status(200).json({ message: '✅ Besked sendt til admin.' });
      } else {
        res.status(400).json({ error: '❌ Ugyldig recipient type.' });
      }
    } catch (error) {
      logger.error('Send chat message failed:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

// ========================= Profile Management ========================= //

/**
 * Get User Profile (Authenticated Users)
 */
app.get(
  '/api/profile',
  authenticateToken,
  asyncHandler(async (req, res) => {
    try {
      const user = await User.findById(req.user.id).select('-password');
      if (!user) {
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }
      res.json({ user });
    } catch (error) {
      logger.error('Get user profile failed:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

/**
 * Update User Profile (Authenticated Users)
 */
app.put(
  '/api/profile',
  authenticateToken,
  upload.single('profilePicture'),
  [
    body('name').optional().trim().notEmpty().withMessage('Navn kan ikke være tomt.').escape(),
    body('phoneNumber')
      .optional()
      .trim()
      .matches(/^[0-9+\-()\s]+$/)
      .withMessage('Ugyldigt telefonnummerformat.')
      .escape(),
    body('bio').optional().trim().escape(),
    body('theme').optional().isIn(['light', 'dark']).withMessage('Tema skal være light eller dark.').escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    const profilePicture = req.file;

    if (!errors.isEmpty()) {
      // If using multer, file is handled separately
      if (profilePicture) {
        fs.unlinkSync(profilePicture.path);
      }
      logger.warn('Update profile failed: Validation errors.', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, phoneNumber, bio, theme } = req.body;

    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        // If using multer, need to remove the uploaded file to prevent orphan files
        if (profilePicture) {
          fs.unlinkSync(profilePicture.path);
        }
        return res.status(404).json({ error: '❌ Bruger ikke fundet.' });
      }

      if (profilePicture) {
        if (user.avatar) {
          const oldAvatarPath = path.join(__dirname, 'public', user.avatar);
          if (fs.existsSync(oldAvatarPath)) {
            fs.unlinkSync(oldAvatarPath);
          }
        }
        user.avatar = `/uploads/${profilePicture.filename}`;
      }

      if (name) user.name = name;
      if (phoneNumber) user.phoneNumber = phoneNumber;
      if (bio) user.bio = bio;
      if (theme) user.theme = theme;

      await user.save();

      logger.info(`User profile updated: ${user.email}`, { userId: user._id });
      res.json({ message: '✅ Profil opdateret.' });
    } catch (error) {
      if (profilePicture) {
        fs.unlinkSync(profilePicture.path);
      }
      logger.error('Update profile failed:', error);
      res.status(500).json({ error: '❌ Internt serverfejl.' });
    }
  })
);

// ========================= Guides API Continued ========================= //

/**
 * Get All Guides (Authenticated Admins or Public)
 * Optional: Implement different access levels if needed
 */
app.get(
  '/apiguides/all',
  authenticateAdmin,
  asyncHandler(async (req, res) => {
    try {
      const guides = await Guide.find().sort({ createdAt: -1 });
      res.json({ guides });
    } catch (error) {
      logger.error('Error fetching all guides:', error);
      res.status(500).json({ error: '❌ Fejl ved hentning af guider.' });
    }
  })
);

/**
 * Serve the Guide Page Based on Category and Slug
 * Already handled above in /articles/:category/:slug route
 */

// ==================== Socket.IO Setup ================== //

io.on('connection', (socket) => {
  logger.info('🔗 Bruger forbundet via Socket.IO');

  // Handle user joining their room
  socket.on('join', (userId) => {
    socket.join(userId);
    logger.info(`Bruger tilsluttet rum: ${userId}`);
  });

  // Handle chat messages
  socket.on('chat message', async (data) => {
    const { userId, message, sender } = data;
    try {
      const chatMessage = new ChatMessage({
        user: userId,
        message,
        sender,
      });
      await chatMessage.save();

      // Broadcast message to the specific user room
      io.to(userId.toString()).emit('chat message', {
        sender,
        message,
        timestamp: chatMessage.timestamp,
      });

      // If sender is admin, you might want to notify the user
      if (sender === 'admin') {
        // Implement any additional logic if needed
      }
    } catch (error) {
      logger.error('Error handling chat message via Socket.IO:', error);
    }
  });

  socket.on('disconnect', () => {
    logger.info('🔌 Bruger afbrudt fra Socket.IO');
  });
});

// ========================= Error Handling ============================= //

/**
 * 404 Handler for API Routes
 */
app.use('/api', (req, res) => {
  res.status(404).json({ error: '❌ Ikke fundet' });
});

/**
 * Error Handler for API Routes
 */
app.use('/api', (err, req, res, next) => {
  logger.error('❌ API Serverfejl:', err.stack);
  res.status(500).json({ error: '❌ Internt serverfejl' });
});

/**
 * 404 Handler for Non-API Routes
 */
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'error', '404.html'));
});

/**
 * General Error Handler for Non-API Routes
 */
app.use((err, req, res, next) => {
  logger.error('❌ Serverfejl:', err.stack);
  res.status(500).sendFile(path.join(__dirname, 'public', 'error', '500.html'));
});

// ================== Start the Server ==================

server.listen(PORT, () => {
  logger.info(`🚀 Server kører på port ${PORT}`);
});