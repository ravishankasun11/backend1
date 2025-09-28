// netlify/functions/api.js
// Main API handler for all backend routes

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');

// MongoDB Models (copy your existing models here)
const userSchema = new mongoose.Schema({
  googleId: String,
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  avatar: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  preferences: {
    notifications: { type: Boolean, default: true },
    language: { type: String, default: 'en' },
    units: { type: String, default: 'metric' }
  }
});

const travelDataSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  destination: { type: String, required: true },
  country: { type: String, required: true },
  travelDate: { type: Date, required: true },
  advisoryLevel: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  weatherData: {
    temperature: Number,
    humidity: Number,
    description: String,
    windSpeed: Number
  },
  safetyInfo: {
    criminalActivity: String,
    terrorism: String,
    naturalDisasters: String,
    healthRisks: String
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

let User, TravelData;
let isConnected = false;

// Database connection
const connectDB = async () => {
  if (isConnected) return;
  
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    User = mongoose.model('User', userSchema);
    TravelData = mongoose.model('TravelData', travelDataSchema);
    isConnected = true;
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
};

// Helper function to handle CORS
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Content-Type': 'application/json'
};

// Main handler
exports.handler = async (event, context) => {
  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: ''
    };
  }

  try {
    await connectDB();
    
    const path = event.path.replace('/.netlify/functions/api', '');
    const method = event.httpMethod;
    const body = event.body ? JSON.parse(event.body) : null;
    const headers = event.headers;

    // Route handling
    switch (true) {
      case path === '/health' && method === 'GET':
        return handleHealth();
        
      case path === '/config' && method === 'GET':
        return handleConfig();
        
      case path === '/auth/google' && method === 'POST':
        return handleGoogleAuth(body);
        
      case path === '/auth/logout' && method === 'POST':
        return handleLogout();
        
      case path === '/travel/advisory' && method === 'POST':
        return handleTravelAdvisory(body, headers);
        
      case path === '/travel/weather' && method === 'GET':
        return handleWeather(event.queryStringParameters);
        
      case path.startsWith('/user/') && method === 'GET':
        return handleUserProfile(path, headers);
        
      default:
        return {
          statusCode: 404,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Route not found' })
        };
    }
  } catch (error) {
    console.error('Function error:', error);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};

// Route handlers
const handleHealth = () => ({
  statusCode: 200,
  headers: corsHeaders,
  body: JSON.stringify({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: isConnected ? 'connected' : 'disconnected',
    version: '1.0.0'
  })
});

const handleConfig = () => ({
  statusCode: 200,
  headers: corsHeaders,
  body: JSON.stringify({
    googleClientId: process.env.GOOGLE_CLIENT_ID,
    environment: process.env.NODE_ENV || 'production'
  })
});

const handleGoogleAuth = async (body) => {
  try {
    const { token } = body;
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    
    let user = await User.findOne({ email: payload.email });
    if (!user) {
      user = await User.create({
        googleId: payload.sub,
        email: payload.email,
        name: payload.name,
        avatar: payload.picture,
        lastLogin: new Date()
      });
    } else {
      user.lastLogin = new Date();
      await user.save();
    }

    const jwtToken = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({
        token: jwtToken,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          avatar: user.avatar
        }
      })
    };
  } catch (error) {
    return {
      statusCode: 401,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Invalid token' })
    };
  }
};

const handleLogout = () => ({
  statusCode: 200,
  headers: corsHeaders,
  body: JSON.stringify({ message: 'Logged out successfully' })
});

const handleTravelAdvisory = async (body, headers) => {
  try {
    // Verify JWT token
    const authHeader = headers.authorization;
    if (!authHeader) {
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'No authorization header' })
      };
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const { destination, country, travelDate } = body;
    
    // Get weather data
    const weatherResponse = await fetch(
      `https://api.openweathermap.org/data/2.5/weather?q=${destination}&appid=${process.env.OPENWEATHER_API_KEY}&units=metric`
    );
    const weatherData = await weatherResponse.json();
    
    // Create travel record
    const travelRecord = await TravelData.create({
      userId: decoded.userId,
      destination,
      country,
      travelDate: new Date(travelDate),
      weatherData: {
        temperature: weatherData.main?.temp || 0,
        humidity: weatherData.main?.humidity || 0,
        description: weatherData.weather?.[0]?.description || 'No data',
        windSpeed: weatherData.wind?.speed || 0
      },
      advisoryLevel: 'low', // You can add more logic here
      safetyInfo: {
        criminalActivity: 'Monitor local conditions',
        terrorism: 'Stay vigilant',
        naturalDisasters: 'Check weather conditions',
        healthRisks: 'Follow health guidelines'
      }
    });

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify(travelRecord)
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: error.message })
    };
  }
};

const handleWeather = async (queryParams) => {
  try {
    const { city } = queryParams;
    if (!city) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'City parameter required' })
      };
    }

    const response = await fetch(
      `https://api.openweathermap.org/data/2.5/weather?q=${city}&appid=${process.env.OPENWEATHER_API_KEY}&units=metric`
    );
    const data = await response.json();

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify(data)
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: error.message })
    };
  }
};

const handleUserProfile = async (path, headers) => {
  try {
    const authHeader = headers.authorization;
    if (!authHeader) {
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'No authorization header' })
      };
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findById(decoded.userId).select('-googleId');
    
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify(user)
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: error.message })
    };
  }
};