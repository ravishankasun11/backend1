const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "https://api.openweathermap.org", "https://www.travel-advisory.info"]
        },
    },
}));

// Enhanced CORS for deployment
app.use(cors({
    origin: [
        'http://localhost:8080',
        'http://127.0.0.1:8080', 
        'http://localhost:3000',
        process.env.FRONTEND_URL,
        // Add your Netlify domain here once deployed
        /\.netlify\.app$/
    ].filter(Boolean),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));

app.use(express.json({ limit: '10mb' }));

// Only serve static files in development
if (process.env.NODE_ENV !== 'production') {
    app.use(express.static(path.join(__dirname, '../frontend')));
}

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.NODE_ENV === 'production' ? 200 : 100,
    message: { error: 'Too many requests from this IP, please try again later.' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.NODE_ENV === 'production' ? 20 : 10,
    message: { error: 'Too many authentication attempts, please try again later.' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);

// Google OAuth2 client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Enhanced MongoDB connection for deployment
const connectDB = async () => {
    try {
        const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/travel_system';
        
        await mongoose.connect(mongoURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            family: 4
        });
        
        console.log('✅ MongoDB connected successfully');
    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        process.exit(1);
    }
};

connectDB();

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('⚠️ MongoDB disconnected');
    if (process.env.NODE_ENV === 'production') {
        // Attempt to reconnect in production
        connectDB();
    }
});

// Schemas
const userSchema = new mongoose.Schema({
    googleId: String,
    email: { 
        type: String, 
        required: true, 
        unique: true,
        lowercase: true,
        trim: true
    },
    name: { type: String, required: true, trim: true },
    picture: String,
    password: String, // for email/password auth
    apiKey: { type: String, unique: true },
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const travelDataSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    city: { type: String, required: true, trim: true },
    country: { type: String, required: true, uppercase: true, trim: true },
    weatherData: {
        temperature: { type: Number, required: true },
        description: { type: String, required: true },
        humidity: { type: Number, required: true },
        windSpeed: { type: Number, required: true },
        visibility: { type: Number, required: true },
        pressure: { type: Number, required: true },
        icon: String
    },
    travelAdvisory: {
        score: { type: Number, required: true, min: 1, max: 5 },
        sources_active: { type: Number, required: true },
        message: { type: String, required: true },
        updated: { type: String, required: true }
    },
    timestamp: { type: Date, default: Date.now },
    aggregatedAt: { type: Date, default: Date.now }
});

// Add indexes for better performance
userSchema.index({ email: 1 });
userSchema.index({ apiKey: 1 });
travelDataSchema.index({ userId: 1, timestamp: -1 });
travelDataSchema.index({ city: 1, country: 1 });

const User = mongoose.model('User', userSchema);
const TravelData = mongoose.model('TravelData', travelDataSchema);

// Utility Functions
function generateApiKey() {
    return 'tk_' + Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15) + 
           Date.now().toString(36);
}

function generateJWT(userId) {
    return jwt.sign(
        { userId }, 
        process.env.JWT_SECRET || 'fallback_secret_key_change_in_production',
        { expiresIn: '24h' }
    );
}

// Middleware
const verifyToken = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ error: 'Access denied. No token provided.' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key_change_in_production');
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user || !user.isActive) {
            return res.status(401).json({ error: 'Invalid token or inactive user.' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ error: 'Invalid token.' });
    }
};

const verifyApiKey = async (req, res, next) => {
    try {
        const apiKey = req.header('X-API-Key');
        
        if (!apiKey) {
            return res.status(401).json({ error: 'API key required.' });
        }

        const user = await User.findOne({ apiKey, isActive: true });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid API key.' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        req.apiUser = user;
        next();
    } catch (error) {
        console.error('API key verification error:', error);
        res.status(401).json({ error: 'Invalid API key.' });
    }
};

// Routes

// Health check with environment info
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        version: '1.0.0'
    });
});

// Configuration endpoint for frontend
app.get('/api/config', (req, res) => {
    res.json({
        googleClientId: process.env.GOOGLE_CLIENT_ID,
        environment: process.env.NODE_ENV || 'development'
    });
});

// Email/Password Registration
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'User with this email already exists.' });
        }

        // Hash password
        const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const user = new User({
            name: name.trim(),
            email: email.toLowerCase().trim(),
            password: hashedPassword,
            apiKey: generateApiKey()
        });

        await user.save();

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                apiKey: user.apiKey
            }
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error during registration.' });
    }
});

// Email/Password Sign In
app.post('/api/auth/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        // Find user
        const user = await User.findOne({ 
            email: email.toLowerCase().trim(),
            isActive: true 
        });

        if (!user || !user.password) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const token = generateJWT(user._id);

        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                picture: user.picture,
                apiKey: user.apiKey
            }
        });

    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ error: 'Internal server error during sign in.' });
    }
});

// Google OAuth login
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'Google token is required.' });
        }
        
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        
        const payload = ticket.getPayload();
        const { sub: googleId, email, name, picture } = payload;

        let user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            // Create new user
            user = new User({
                googleId,
                email: email.toLowerCase(),
                name,
                picture,
                apiKey: generateApiKey()
            });
            await user.save();
        } else {
            // Update existing user
            if (!user.apiKey) {
                user.apiKey = generateApiKey();
            }
            user.googleId = googleId;
            user.picture = picture;
            user.lastLogin = new Date();
            await user.save();
        }

        const jwtToken = generateJWT(user._id);

        res.json({
            token: jwtToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                picture: user.picture,
                apiKey: user.apiKey
            }
        });

    } catch (error) {
        console.error('Google auth error:', error);
        res.status(401).json({ error: 'Invalid Google token' });
    }
});

// Submit travel data (requires JWT token, API key is optional for additional verification)
app.post('/api/travel-data', verifyToken, async (req, res) => {
    try {
        // Optional API key verification for additional security
        const apiKey = req.header('X-API-Key');
        if (apiKey && req.user.apiKey !== apiKey) {
            return res.status(401).json({ error: 'API key does not match user.' });
        }

        const { city, country, weatherData, travelAdvisory } = req.body;

        // Validation
        if (!city || !country || !weatherData || !travelAdvisory) {
            return res.status(400).json({ error: 'Missing required data fields' });
        }

        // Validate weather data structure
        const requiredWeatherFields = ['temperature', 'description', 'humidity', 'windSpeed', 'visibility', 'pressure'];
        for (const field of requiredWeatherFields) {
            if (weatherData[field] === undefined || weatherData[field] === null) {
                return res.status(400).json({ error: `Missing weather field: ${field}` });
            }
        }

        // Validate advisory data structure
        const requiredAdvisoryFields = ['score', 'sources_active', 'message', 'updated'];
        for (const field of requiredAdvisoryFields) {
            if (travelAdvisory[field] === undefined || travelAdvisory[field] === null) {
                return res.status(400).json({ error: `Missing advisory field: ${field}` });
            }
        }

        // Validate score range
        if (travelAdvisory.score < 1 || travelAdvisory.score > 5) {
            return res.status(400).json({ error: 'Advisory score must be between 1 and 5' });
        }

        const travelData = new TravelData({
            userId: req.user._id,
            city: city.trim(),
            country: country.toUpperCase().trim(),
            weatherData: {
                temperature: Number(weatherData.temperature),
                description: weatherData.description.trim(),
                humidity: Number(weatherData.humidity),
                windSpeed: Number(weatherData.windSpeed),
                visibility: Number(weatherData.visibility),
                pressure: Number(weatherData.pressure),
                icon: weatherData.icon || null
            },
            travelAdvisory: {
                score: Number(travelAdvisory.score),
                sources_active: Number(travelAdvisory.sources_active),
                message: travelAdvisory.message.trim(),
                updated: travelAdvisory.updated
            }
        });

        await travelData.save();

        res.status(201).json({
            message: 'Travel data stored successfully',
            id: travelData._id,
            timestamp: travelData.timestamp
        });

    } catch (error) {
        console.error('Error storing travel data:', error);
        
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ error: `Validation error: ${errors.join(', ')}` });
        }
        
        res.status(500).json({ error: 'Internal server error while storing data.' });
    }
});

// Get stored records
app.get('/api/records', verifyToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 10, 50); // Max 50 records per request
        const skip = (page - 1) * limit;

        // Optional filters
        const filters = { userId: req.user._id };
        if (req.query.city) {
            filters.city = new RegExp(req.query.city, 'i');
        }
        if (req.query.country) {
            filters.country = req.query.country.toUpperCase();
        }

        const records = await TravelData.find(filters)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit)
            .populate('userId', 'name email')
            .lean();

        const total = await TravelData.countDocuments(filters);

        res.json({
            records,
            pagination: {
                current: page,
                total: Math.ceil(total / limit),
                hasNext: skip + limit < total,
                hasPrev: page > 1,
                totalRecords: total
            }
        });

    } catch (error) {
        console.error('Error fetching records:', error);
        res.status(500).json({ error: 'Internal server error while fetching records.' });
    }
});

// Get user profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id)
            .select('-password -__v')
            .lean();
        
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json(user);

    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Internal server error while fetching profile.' });
    }
});

// Update user profile
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { name } = req.body;
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({ error: 'Name is required.' });
        }

        const user = await User.findByIdAndUpdate(
            req.user._id,
            { 
                name: name.trim(),
                updatedAt: new Date()
            },
            { new: true }
        ).select('-password -__v');

        res.json({
            message: 'Profile updated successfully',
            user
        });

    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ error: 'Internal server error while updating profile.' });
    }
});

// Regenerate API key
app.post('/api/user/regenerate-api-key', verifyToken, async (req, res) => {
    try {
        const newApiKey = generateApiKey();
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { 
                apiKey: newApiKey,
                updatedAt: new Date()
            },
            { new: true }
        ).select('-password -__v');

        res.json({
            message: 'API key regenerated successfully',
            apiKey: newApiKey
        });

    } catch (error) {
        console.error('Error regenerating API key:', error);
        res.status(500).json({ error: 'Internal server error while regenerating API key.' });
    }
});

// Delete user account
app.delete('/api/user/account', verifyToken, async (req, res) => {
    try {
        // Soft delete - mark as inactive
        await User.findByIdAndUpdate(req.user._id, { 
            isActive: false,
            updatedAt: new Date()
        });

        // Optionally delete all user's travel data
        await TravelData.deleteMany({ userId: req.user._id });

        res.json({ message: 'Account deactivated successfully' });

    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ error: 'Internal server error while deleting account.' });
    }
});

// API-only endpoint for submitting data with just API key (no JWT required)
app.post('/api/external/travel-data', verifyApiKey, async (req, res) => {
    try {
        const { city, country, weatherData, travelAdvisory } = req.body;

        // Validation (same as JWT endpoint)
        if (!city || !country || !weatherData || !travelAdvisory) {
            return res.status(400).json({ error: 'Missing required data fields' });
        }

        const requiredWeatherFields = ['temperature', 'description', 'humidity', 'windSpeed', 'visibility', 'pressure'];
        for (const field of requiredWeatherFields) {
            if (weatherData[field] === undefined || weatherData[field] === null) {
                return res.status(400).json({ error: `Missing weather field: ${field}` });
            }
        }

        const requiredAdvisoryFields = ['score', 'sources_active', 'message', 'updated'];
        for (const field of requiredAdvisoryFields) {
            if (travelAdvisory[field] === undefined || travelAdvisory[field] === null) {
                return res.status(400).json({ error: `Missing advisory field: ${field}` });
            }
        }

        if (travelAdvisory.score < 1 || travelAdvisory.score > 5) {
            return res.status(400).json({ error: 'Advisory score must be between 1 and 5' });
        }

        const travelData = new TravelData({
            userId: req.apiUser._id,
            city: city.trim(),
            country: country.toUpperCase().trim(),
            weatherData: {
                temperature: Number(weatherData.temperature),
                description: weatherData.description.trim(),
                humidity: Number(weatherData.humidity),
                windSpeed: Number(weatherData.windSpeed),
                visibility: Number(weatherData.visibility),
                pressure: Number(weatherData.pressure),
                icon: weatherData.icon || null
            },
            travelAdvisory: {
                score: Number(travelAdvisory.score),
                sources_active: Number(travelAdvisory.sources_active),
                message: travelAdvisory.message.trim(),
                updated: travelAdvisory.updated
            }
        });

        await travelData.save();

        res.status(201).json({
            message: 'Travel data stored successfully',
            id: travelData._id,
            timestamp: travelData.timestamp
        });

    } catch (error) {
        console.error('Error storing travel data (API):', error);
        
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ error: `Validation error: ${errors.join(', ')}` });
        }
        
        res.status(500).json({ error: 'Internal server error while storing data.' });
    }
});

// Don't serve frontend files in production (frontend will be deployed separately)
if (process.env.NODE_ENV !== 'production') {
    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, '../frontend/index.html'));
    });
}

// Global error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    
    if (error.name === 'CastError') {
        return res.status(400).json({ error: 'Invalid ID format' });
    }
    
    if (error.code === 11000) {
        return res.status(409).json({ error: 'Duplicate entry detected' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 SIGTERM received, shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🛑 SIGINT received, shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️ MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting...'}`);
    console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:8080'}`);
});