# Travel Advisory & Weather System

A minimalist travel information system built with Nothing OS design principles. Get real-time weather data and safety advisories for destinations worldwide.

## Features

- **Real-time Weather Data**: Live weather information from OpenWeatherMap
- **Travel Safety Advisories**: Up-to-date travel warnings and risk assessments
- **User Authentication**: Email/password and Google OAuth support
- **Data Persistence**: Save and track your travel research
- **Minimalist Design**: Nothing OS inspired black and white interface
- **Secure API**: Rate limiting, JWT tokens, and API key authentication

## Tech Stack

### Frontend
- HTML5 / CSS3 / Vanilla JavaScript
- JetBrains Mono font (Nothing OS style)
- Glass morphism effects
- Responsive design

### Backend
- Node.js / Express.js
- MongoDB with Mongoose
- JWT authentication
- Google OAuth 2.0
- Rate limiting and security middleware

### External APIs
- OpenWeatherMap API
- Travel Advisory API

## Quick Start

### Prerequisites
- Node.js (v16 or higher)
- MongoDB
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/travel-advisory-system.git
   cd travel-advisory-system
   ```

2. **Setup Backend**
   ```bash
   cd backend
   npm install
   cp .env.example .env
   ```

3. **Configure Environment Variables**
   Edit `.env` file with your credentials:
   ```env
   MONGODB_URI=mongodb://localhost:27017/travel_system
   JWT_SECRET=your_super_secret_jwt_key
   GOOGLE_CLIENT_ID=your_google_client_id
   OPENWEATHER_API_KEY=your_openweather_api_key
   ```

4. **Start MongoDB**
   ```bash
   # Using MongoDB service
   sudo systemctl start mongod
   
   # Or using Docker
   docker run -d -p 27017:27017 --name mongodb mongo:latest
   ```

5. **Start the Backend Server**
   ```bash
   npm run dev
   ```

6. **Serve Frontend** (in a new terminal)
   ```bash
   cd frontend
   # Using Python
   python -m http.server 8080
   
   # Or using Node.js
   npx serve -p 8080
   
   # Or using PHP
   php -S localhost:8080
   ```

7. **Access the Application**
   Open your browser to `http://localhost:8080`

## API Endpoints

### Authentication
- `POST /api/auth/signup` - Create new account
- `POST /api/auth/signin` - Sign in with email/password
- `POST /api/auth/google` - Google OAuth authentication

### Travel Data
- `POST /api/travel-data` - Save travel information
- `GET /api/records` - Get saved records
- `GET /api/user/profile` - Get user profile

### System
- `GET /api/health` - Health check

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NODE_ENV` | Environment (development/production) | No |
| `PORT` | Server port | No (default: 3000) |
| `MONGODB_URI` | MongoDB connection string | Yes |
| `JWT_SECRET` | JWT signing secret | Yes |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes |
| `OPENWEATHER_API_KEY` | OpenWeatherMap API key | Yes |
| `FRONTEND_URL` | Frontend URL for CORS | No |

## File Structure

```
travel-advisory-system/
├── frontend/
│   ├── index.html              # Login page
│   ├── dashboard.html          # Main dashboard
│   └── assets/
│       ├── css/
│       │   ├── global.css      # Global styles
│       │   ├── auth.css        # Authentication styles
│       │   └── dashboard.css   # Dashboard styles
│       └── js/
│           ├── auth.js         # Authentication logic
│           ├── dashboard.js    # Dashboard functionality
│           └── api.js          # API utilities
├── backend/
│   ├── server.js               # Express server
│   ├── package.json           # Dependencies
│   └── .env                   # Environment variables
├── .gitignore
└── README.md
```

## Design Philosophy

This project follows Nothing OS design principles:

- **Minimalism**: Clean black and white interface
- **Typography**: Monospaced JetBrains Mono font
- **Transparency**: Glass morphism effects
- **Functionality**: Focus on essential features
- **Performance**: Optimized animations and interactions

## Security Features

- JWT token authentication
- Rate limiting on API endpoints
- Input validation and sanitization
- CORS protection
- Helmet security headers
- Password hashing with bcrypt
- API key verification

## Development

### Running in Development Mode

```bash
# Backend (with auto-reload)
cd backend
npm run dev

# Frontend (any static server)
cd frontend
python -m http.server 8080
```

### Testing

```bash
cd backend
npm test
```

### Linting

```bash
cd backend
npm run lint
npm run lint:fix
```

## API Keys Setup

### OpenWeatherMap API
1. Visit [OpenWeatherMap](https://openweathermap.org/api)
2. Create account and get API key
3. Add to `.env` file

### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create project and enable Google+ API
3. Create OAuth 2.0 credentials
4. Add authorized origins: `http://localhost:8080`
5. Add client ID to `.env` file

## Deployment

### Production Setup

1. **Environment Variables**
   ```env
   NODE_ENV=production
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/travel_system
   JWT_SECRET=your_production_jwt_secret
   ```

2. **Build and Start**
   ```bash
   cd backend
   npm install --production
   npm start
   ```

### Docker Deployment

```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY backend/ ./
RUN npm install --production
EXPOSE 3000
CMD ["npm", "start"]
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, email support@example.com or create an issue on GitHub.

## Roadmap

- [ ] Mobile app version
- [ ] Email notifications
- [ ] Travel itinerary planning
- [ ] Weather alerts
- [ ] Offline mode
- [ ] Multi-language support

## Acknowledgments

- Nothing OS for design inspiration
- OpenWeatherMap for weather data
- Travel Advisory Info for safety data
- JetBrains for the Mono font