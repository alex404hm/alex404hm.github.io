import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { body, validationResult } from 'express-validator';
import asyncHandler from 'express-async-handler';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import morgan from 'morgan';
import winston from 'winston';

// Initialize Environment
dotenv.config();

// Initialize Express App
const app = express();

// Configuration
const PORT = process.env.PORT1 || 3001;
const MONGODB_URI = process.env.MONGODB_URI;

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/server.log' }),
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

// Database Connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => logger.info('🌟 Connected to MongoDB'))
  .catch(err => {
    logger.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Define Schemas and Models
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
  publishDate: { type: Date, default: Date.now },
  views: { type: Number, default: 0, index: true },
}, { timestamps: true });

// Index for fast lookup of slug within category
guideSchema.index({ slug: 1, category: 1 }, { unique: true });

const Guide = mongoose.model('Guide', guideSchema);

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

// Middleware Setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(dirname(fileURLToPath(import.meta.url)), 'public')));
app.use(morgan('dev'));

// Route Definitions
app.get(
  '/apiguides',
  asyncHandler(async (req, res) => {
    const guides = await Guide.find().sort({ createdAt: -1 });
    res.json({ guides });
  })
);

app.post(
  '/apiguides',
  [
    body('title').trim().notEmpty().withMessage('Title is required.').escape(),
    body('content').trim().notEmpty().withMessage('Content is required.').escape(),
    body('category').trim().notEmpty().withMessage('Category is required.').escape(),
    body('subtitle').optional().trim().escape(),
    body('summary').optional().trim().escape(),
    body('tags').optional().isArray().withMessage('Tags must be an array.'),
    body('tags.*').optional().trim().escape(),
    body('bannerImage').optional().trim().escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, subtitle, summary, content, tags, category, bannerImage, author } = req.body;
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
      author,
      publishDate: new Date().toLocaleDateString(),
    });

    const savedGuide = await newGuide.save();
    res.status(201).json(savedGuide);
  })
);

app.get(
  '/apiguides/:category/:slug',
  asyncHandler(async (req, res) => {
    const { category, slug } = req.params;
    const guide = await Guide.findOne({
      category: new RegExp(`^${category}$`, 'i'),
      slug: new RegExp(`^${slug}$`, 'i'),
    });

    if (!guide) {
      return res.status(404).sendFile(join(dirname(fileURLToPath(import.meta.url)), 'public', 'error', '404.html'));
    }

    guide.views += 1;
    await guide.save();

    res.sendFile(join(dirname(fileURLToPath(import.meta.url)), 'public', 'template.html'));
  })
);

app.put(
  '/apiguides/:id',
  [
    body('title').optional().trim().notEmpty().escape(),
    body('content').optional().trim().notEmpty().escape(),
    body('category').optional().trim().notEmpty().escape(),
    body('subtitle').optional().trim().escape(),
    body('summary').optional().trim().escape(),
    body('tags').optional().isArray().withMessage('Tags must be an array.'),
    body('tags.*').optional().trim().escape(),
    body('bannerImage').optional().trim().escape(),
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const updates = { ...req.body };
    if (req.body.title || req.body.category) {
      const currentGuide = await Guide.findById(req.params.id);
      if (!currentGuide) {
        return res.status(404).json({ error: '❌ Guide not found.' });
      }
      updates.slug = await createUniqueSlug(req.body.title || currentGuide.title, req.body.category || currentGuide.category);
    }

    const updatedGuide = await Guide.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
    if (!updatedGuide) {
      return res.status(404).json({ error: '❌ Guide not found.' });
    }
    res.json(updatedGuide);
  })
);

app.delete(
  '/apiguides/:id',
  asyncHandler(async (req, res) => {
    const deletedGuide = await Guide.findByIdAndDelete(req.params.id);
    if (!deletedGuide) {
      return res.status(404).json({ error: '❌ Guide not found.' });
    }
    res.json({ message: '✅ Guide deleted.' });
  })
);

// Start the Server
app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
});