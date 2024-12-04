require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const MongoStore = require('connect-mongo');

// Initialize Express app
const app = express();

// Middleware setup
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'supportpro-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions'
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24, // 1 day
  },
}));

// Set public folder
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB setup
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('Failed to connect to MongoDB', err);
});

// Example: Define schema for User to track admins
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  isAdmin: Boolean,
  isVerified: Boolean,
});
const User = mongoose.model('User', userSchema);

// Socket.IO setup
const server = http.createServer(app);
const io = new Server(server);

io.on('connection', (socket) => {
  console.log('User connected');
  
  socket.on('chat message', (msg) => {
    io.emit('chat message', msg);
  });
  
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Middleware to check authentication for dashboard and admin routes
function verifyAuth(req, res, next) {
  if (!req.session.isLoggedIn) {
    if (req.originalUrl.startsWith('/admin')) {
      return res.redirect('/admin/login');
    } else if (req.originalUrl.startsWith('/dashboard')) {
      return res.redirect('/dashboard/login');
    }
  }
  next();
}

function verifyAdmin(req, res, next) {
  const currentUser = req.session.user;
  if (!currentUser) {
    return res.redirect('/admin/login');
  }

  User.findOne({ _id: currentUser.id, isAdmin: true }, (err, user) => {
    if (err || !user) {
      return res.status(403).send('Access denied. Admins only.');
    }
    next();
  });
}

// Verification middleware for dashboard access
function verifyEmail(req, res, next) {
  if (req.session.user && !req.session.user.isVerified) {
    return res.sendFile(path.join(__dirname, 'public', 'verify.html'));
  }
  next();
}

// Routes
// Landing and start pages (updated as per your request)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html')); // The landing page can be customized further as needed.
});

// Authentication page
app.get('/auth', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth', 'auth.html'));
});

// Dashboard routes
app.use('/dashboard', verifyAuth, verifyEmail);
app.get('/dashboard/windows', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'windows.html'));
});
app.get('/dashboard/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'profile.html'));
});

// Admin routes
app.use('/admin', verifyAuth, verifyAdmin);
app.get('/admin/tickets', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'tickets.html'));
});
app.get('/admin/guides', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'guides.html'));
});
app.get('/admin/users', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'users.html'));
});

// Search API for guides
app.get('/api/guides/search', async (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter is required' });
  }

  // Replace with actual database lookup in MongoDB (example collection: Guides)
  const guides = [
    { id: 1, title: 'Guide 1', content: 'Content of guide 1' },
    { id: 2, title: 'Guide 2', content: 'Content of guide 2' },
  ];

  const results = guides.filter(guide =>
    guide.title.toLowerCase().includes(query.toLowerCase()) ||
    guide.content.toLowerCase().includes(query.toLowerCase())
  );

  res.json(results);
});

// Email verification endpoint
app.post('/send-verification-email', (req, res) => {
  const email = req.session.user?.email;

  if (!email) {
    return res.status(400).send('User not logged in or email missing.');
  }

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Please verify your email',
    text: 'Click the link to verify your email: <verification_link>',
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending verification email:', error);
      return res.redirect('/auth/error.html');
    } else {
      console.log('Verification email sent: ' + info.response);
      res.send('Verification email sent.');
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong! Please try again later.');
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
