# Travel Advisory Backend - Netlify Functions

This is the serverless backend for the Travel Advisory System built using Netlify Functions.

## Features

- Google OAuth Authentication
- Travel Advisory Generation
- Weather Data Integration
- User Profile Management
- MongoDB Database Integration

## API Endpoints

- `GET /api/health` - Health check
- `GET /api/config` - Configuration data
- `POST /api/auth/google` - Google OAuth login
- `POST /api/auth/logout` - User logout
- `POST /api/travel/advisory` - Generate travel advisory
- `GET /api/travel/weather` - Get weather data
- `GET /api/user/profile` - Get user profile

## Environment Variables

Required environment variables:

```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
OPENWEATHER_API_KEY=your_openweather_api_key
NODE_ENV=production
```

## Deployment

This project is designed to be deployed on Netlify. The `netlify.toml` file contains all necessary configuration.

1. Push to GitHub
2. Connect to Netlify
3. Add environment variables
4. Deploy automatically

## Local Development

```bash
npm install
netlify dev
```