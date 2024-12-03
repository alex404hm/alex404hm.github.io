// Import required modules
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const asyncHandler = require('express-async-handler');

// Load environment variables
dotenv.config();

// Initialize the app
const app = express();
const port = process.env.PORT1 || 3001;

// MongoDB connection setup
const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/adminDashboard';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// Define User, Ticket, and Guide schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  timestamp: { type: Date, default: Date.now },
  description: { type: String, default: '' },
});

const ticketSchema = new mongoose.Schema({
  title: { type: String, required: true },
  status: { type: String, enum: ['open', 'closed'], default: 'open' },
  timestamp: { type: Date, default: Date.now },
  description: { type: String, default: '' },
});

const guideSchema = new mongoose.Schema({
  id: { type: String, unique: true, default: uuidv4 },
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

// Define User, Ticket, and Guide models
const User = mongoose.model('User', userSchema);
const Ticket = mongoose.model('Ticket', ticketSchema);
const Guide = mongoose.model('Guide', guideSchema);

// Middleware setup
app.use(cors());
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());

// Configure the Google OAuth Strategy
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3001/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Find or create user in the database
      let user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = await User.create({
          name: profile.displayName,
          email: profile.emails[0].value,
          description: 'Oprettede en ny bruger via Google OAuth.'
        });
      }
      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

// Serialize user information into the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user information from the session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes for OAuth
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect to dashboard
    res.redirect('/dashboard');
  }
);

// Middleware to ensure authentication for protected routes
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Protected route example
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.send(`Welcome to your dashboard, ${req.user.name}!`);
});

// Login route
app.get('/login', (req, res) => {
  res.send('Please login to access your dashboard.');
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Helper function to simulate data fetching delay
const simulateDelay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Route to import sample data into the database
app.post('/api/import-data', asyncHandler(async (req, res) => {
  const sampleUsers = [
    { name: 'Jens Petersen', email: 'jens@example.com', description: 'Oprettede en ny bruger.' },
    { name: 'Maria Hansen', email: 'maria@example.com', description: 'Lukkede en ticket.' },
  ];
  const sampleTickets = [
    { title: 'Issue #1', status: 'open', description: 'Bruger Jens Petersen oprettede en ny ticket.' },
    { title: 'Issue #2', status: 'closed', description: 'Bruger Maria Hansen lukkede en ticket.' },
  ];
  const sampleGuides = [
    { title: 'Sådan åbner du en support ticket', content: 'Dette er en guide til at åbne en support ticket.', category: 'Support' },
    { title: 'Fejlfinding af netværksproblemer', content: 'Dette er en guide til fejlfinding af netværksproblemer.', category: 'Netværk' },
  ];
  await User.insertMany(sampleUsers);
  await Ticket.insertMany(sampleTickets);
  await Guide.insertMany(sampleGuides);
  res.status(200).json({ message: 'Sample data imported successfully.' });
}));

// Route to get dashboard data
app.get('/api/dashboard-data', asyncHandler(async (req, res) => {
  await simulateDelay(500);
  const totalUsers = await User.countDocuments();
  const openTickets = await Ticket.countDocuments({ status: 'open' });
  const closedTickets = await Ticket.countDocuments({ status: 'closed' });
  const recentUsers = await User.find().sort({ timestamp: -1 }).limit(5);
  const recentTickets = await Ticket.find().sort({ timestamp: -1 }).limit(5);
  const recentActivities = [...recentUsers, ...recentTickets]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 5)
    .map(activity => ({ description: activity.description, timestamp: activity.timestamp }));
  res.json({ totalUsers, openTickets, closedTickets, recentActivities });
}));

// Route to get all users
app.get('/api/users', asyncHandler(async (req, res) => {
  const users = await User.find().sort({ timestamp: -1 });
  res.json({ users });
}));

// Route to get all tickets
app.get('/api/tickets', asyncHandler(async (req, res) => {
  const tickets = await Ticket.find().sort({ timestamp: -1 });
  res.json({ tickets });
}));

// Route to get all guides
app.get('/api/guides', asyncHandler(async (req, res) => {
  const guides = await Guide.find().sort({ timestamp: -1 });
  res.json({ guides });
}));

// Route to add a new guide
app.post('/api/guides', asyncHandler(async (req, res) => {
  const { title, content, category } = req.body;
  if (!title || !content || !category) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  const newGuide = new Guide({ title, content, category });
  await newGuide.save();
  res.status(201).json({ message: 'Guide added successfully', guide: newGuide });
}));

// Route to delete a guide
app.delete('/api/guides/:id', asyncHandler(async (req, res) => {
  const guideId = req.params.id;
  const guide = await Guide.findByIdAndDelete(guideId);
  if (!guide) {
    return res.status(404).json({ message: 'Guide not found' });
  }
  res.status(200).json({ message: 'Guide deleted successfully' });
}));

// 404 Error handling for unknown routes
app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
