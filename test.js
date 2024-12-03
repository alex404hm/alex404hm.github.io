import express from 'express';
import cors from 'cors';
import http from 'http';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { Server } from 'socket.io';

dotenv.config(); // Load environment variables from .env file

// Express App and Server Configurations
const app = express();
const PORT = process.env.PORT1 || 3001; // Set port from env or default to 3001
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/support_pro';

// Middleware
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
app.use(express.json());

// Create HTTP server and wrap the express app
const server = http.createServer(app);

// Connect to MongoDB using Mongoose
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ MongoDB Connected successfully...'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Define Mongoose Schema and Model
const guideSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subtitle: String,
  summary: String,
  content: { type: String, required: true },
  tags: [String],
  category: { type: String, required: true },
  bannerImage: String,
  author: {
    name: String,
    title: String,
    photo: String,
    quote: String,
  },
  publishDate: String,
  views: { type: Number, default: 0 },
}, { timestamps: true });

guideSchema.index({ title: 1, category: 1 }, { unique: true }); // Ensure unique title-category combination

const Guide = mongoose.model('Guide', guideSchema);

// Socket.IO for Real-time Chat
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

let chatSessions = {};

// Socket.IO Connections for Real-time Chat
io.on('connection', (socket) => {
  console.log(`🟢 User connected: ${socket.id}`);

  socket.on('join_chat', ({ ticketId, userName }) => {
    socket.join(ticketId);
    chatSessions[ticketId] = chatSessions[ticketId] || [];
    socket.emit('chat_history', chatSessions[ticketId]);
    console.log(`📬 ${userName} joined chat for ticket ${ticketId}`);
  });

  socket.on('send_message', ({ ticketId, userName, message }) => {
    const chatMessage = { user: userName, message, timestamp: new Date().toISOString() };
    chatSessions[ticketId] = chatSessions[ticketId] || [];
    chatSessions[ticketId].push(chatMessage);
    io.to(ticketId).emit('receive_message', chatMessage);
  });

  socket.on('disconnect', () => {
    console.log(`🔴 User disconnected: ${socket.id}`);
  });
});

// Middleware to simulate user authentication for author data
const mockUserMiddleware = (req, res, next) => {
  req.user = {
    name: 'John Doe',
    title: 'IT Specialist',
    photo: 'https://example.com/johndoe.jpg',
    quote: 'Always here to help.',
  };
  next();
};

app.use(mockUserMiddleware);

// API Endpoints

/**
 * Fetch a single guide by ID.
 */
app.get('/api/guides/:id', async (req, res) => {
  try {
    const guide = await Guide.findById(req.params.id);
    if (!guide) {
      return res.status(404).json({ error: 'Guide not found.' });
    }
    res.json(guide);
  } catch (error) {
    console.error('❌ Error fetching guide:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * Fetch all guides, with optional filtering by category, tag, or search.
 */
app.get('/api/guides', async (req, res) => {
  try {
    const { category, tag, search } = req.query;
    let query = {};

    if (category) query.category = new RegExp(category, 'i');
    if (tag) query.tags = new RegExp(tag, 'i');
    if (search) query.$or = [
      { title: new RegExp(search, 'i') },
      { summary: new RegExp(search, 'i') },
      { content: new RegExp(search, 'i') }
    ];

    const guides = await Guide.find(query);
    res.json({ guides });
  } catch (error) {
    console.error('❌ Error fetching guides:', error);
    res.status(500).json({ error: 'Error fetching guides.' });
  }
});

/**
 * Create a new guide.
 */
app.post('/api/guides', async (req, res) => {
  try {
    console.log('Received request body:', req.body); // Log the received request body
    const { title, subtitle, summary, content, tags, category, bannerImage } = req.body;

    // Basic validation checks without Joi
    if (!title || typeof title !== 'string') {
      console.error('❌ Validation Error: Invalid title');
      return res.status(400).json({ error: 'Title must be a non-empty string.' });
    }
    if (!content || typeof content !== 'string') {
      console.error('❌ Validation Error: Invalid content');
      return res.status(400).json({ error: 'Content must be a non-empty string.' });
    }
    if (!category || typeof category !== 'string') {
      console.error('❌ Validation Error: Invalid category');
      return res.status(400).json({ error: 'Category must be a valid non-empty string.' });
    }

    const newGuide = new Guide({
      title,
      subtitle: subtitle || '',
      summary: summary || '',
      content,
      tags: Array.isArray(tags) ? tags : [],
      category,
      bannerImage: bannerImage || '',
      author: req.user, // Use user information from middleware
      publishDate: new Date().toLocaleDateString(),
    });

    const savedGuide = await newGuide.save();
    res.status(201).json(savedGuide);
  } catch (error) {
    if (error.code === 11000) {
      console.error('❌ Duplicate key error:', error);
      res.status(400).json({ error: 'A guide with the same title and category already exists.' });
    } else {
      console.error('❌ Error creating guide:', error);
      res.status(500).json({ error: 'Error creating guide.' });
    }
  }
});

/**
 * Update an existing guide.
 */
app.put('/api/guides/:id', async (req, res) => {
  try {
    console.log('Received update request body:', req.body); // Log the received request body
    const { title, content, category } = req.body;

    // Optional validation checks before updating
    if (title && typeof title !== 'string') {
      console.error('❌ Validation Error: Invalid title during update');
      return res.status(400).json({ error: 'Title must be a non-empty string.' });
    }
    if (content && typeof content !== 'string') {
      console.error('❌ Validation Error: Invalid content during update');
      return res.status(400).json({ error: 'Content must be a non-empty string.' });
    }
    if (category && typeof category !== 'string') {
      console.error('❌ Validation Error: Invalid category during update');
      return res.status(400).json({ error: 'Category must be a valid non-empty string.' });
    }

    const updatedGuide = await Guide.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedGuide) {
      return res.status(404).json({ error: 'Guide not found.' });
    }
    res.json(updatedGuide);
  } catch (error) {
    console.error('❌ Error updating guide:', error);
    res.status(500).json({ error: 'Error updating guide.' });
  }
});

/**
 * Delete a guide by ID.
 */
app.delete('/api/guides/:id', async (req, res) => {
  try {
    const deletedGuide = await Guide.findByIdAndDelete(req.params.id);
    if (!deletedGuide) {
      return res.status(404).json({ error: 'Guide not found.' });
    }
    res.json({ message: 'Guide deleted successfully.' });
  } catch (error) {
    console.error('❌ Error deleting guide:', error);
    res.status(500).json({ error: 'Error deleting guide.' });
  }
});

/**
 * Get popular guides sorted by views.
 */
app.get('/api/guides/popular', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const popularGuides = await Guide.find().sort({ views: -1 }).limit(limit);
    res.json({ guides: popularGuides });
  } catch (error) {
    console.error('❌ Error fetching popular guides:', error);
    res.status(500).json({ error: 'Error fetching popular guides.' });
  }
});

/**
 * Fetch a guide by category and title.
 */
app.get('/api/guides/:category/:title', async (req, res) => {
  try {
    const { category, title } = req.params;
    const guide = await Guide.findOne({ category: new RegExp(category, 'i'), title: new RegExp(title, 'i') });
    if (!guide) {
      return res.status(404).json({ error: 'Guide not found.' });
    }
    res.json(guide);
  } catch (error) {
    console.error('❌ Error fetching guide by category and title:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Start the server
server.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
