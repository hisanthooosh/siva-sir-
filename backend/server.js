// Import required packages
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/auth');
const circularRoutes = require('./routes/circulars');
const systemRoutes = require('./routes/systems');
const userRoutes = require('./routes/users');
const signatoryRoutes = require('./routes/signatories');

// Initialize the app
const app = express();

// --- Middlewares ---

// 1. Enable CORS (Allows frontend at localhost:5173 to talk to backend)
app.use(cors());

// 2. Parse JSON bodies (CRITICAL for receiving login data)
app.use(express.json());

// 3. Debugging Middleware (Logs incoming requests to the terminal)
app.use((req, res, next) => {
  console.log(`👉 Incoming Request: ${req.method} ${req.url}`);

  if (req.body && Object.keys(req.body).length > 0) {
    console.log('📦 Request Body:', req.body);
  }

  next();
});


// --- Database Connection ---
const mongoURI = process.env.MONGO_URI;

const connectDB = async () => {
  try {
    await mongoose.connect(mongoURI);
    // Note: The options object is deprecated in newer Mongoose versions, 
    // but if you are using an older version, your previous options were fine.
    console.log('✅ Successfully connected to MongoDB!');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1); // Stop server if DB fails
  }
};
connectDB();

// --- API Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/circulars', circularRoutes);
app.use('/api/systems', systemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/signatories', signatoryRoutes);

// Test Route
app.get('/', (req, res) => {
  res.send('Circular Portal Backend is running!');
});

// --- Start the Server ---
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`🚀 Server is running on port ${port}`);
});